package sqlitestore

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/agentnameservice/agent-trust-discovery/internal/domain"
	"github.com/agentnameservice/agent-trust-discovery/internal/port"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
	// maxPage caps the 1-based page number so (page-1)*size cannot overflow
	// int and become negative — SQLite treats a negative OFFSET as 0 and would
	// silently return page 1, masking the pathological input. 100_000 pages ×
	// 100 rows/page = 10M rows, orders of magnitude above any realistic use.
	maxPage     = 100_000
	tokenPrefix = "p:"
)

// filterSQL is the assembled WHERE/JOIN/ORDER fragments plus their args. Built
// once and reused by the list and (optional) count queries.
type filterSQL struct {
	where   []string
	args    []any
	joins   string
	ordered string
}

// Search runs an FTS5 + equality-filtered query with offset pagination (design
// §5.1). All SQL fragments are package constants or "?" placeholders; every
// caller value is bound as a parameter.
func (d *DB) Search(ctx context.Context, q port.SearchQuery) (port.SearchPage, error) {
	f := buildFilters(q)
	whereSQL := ""
	if len(f.where) > 0 {
		whereSQL = " WHERE " + strings.Join(f.where, " AND ")
	}

	page := effectivePage(q)
	size := clampSize(q.PageSize)
	offset := (page - 1) * size

	// SQL fragments are package constants + "?" placeholders; all caller values
	// are bound as parameters below.
	listSQL := "SELECT " + agentColumns + " FROM agents" + f.joins + whereSQL + f.ordered + " LIMIT ? OFFSET ?"
	listArgs := make([]any, 0, len(f.args)+2)
	listArgs = append(listArgs, f.args...)
	listArgs = append(listArgs, size+1, offset) // peek one extra row to detect a next page

	items, err := d.queryAgents(ctx, listSQL, listArgs)
	if err != nil {
		return port.SearchPage{}, err
	}
	hasNext := len(items) > size
	if hasNext {
		items = items[:size]
	}

	out := port.SearchPage{Items: items}
	if page > 1 {
		out.PrevToken = encodeToken(page - 1)
	}
	if hasNext {
		out.NextToken = encodeToken(page + 1)
	}

	if q.TotalRequired {
		total, err := d.count(ctx, f, whereSQL)
		if err != nil {
			return port.SearchPage{}, err
		}
		out.TotalItems = total
		out.TotalPages = (total + size - 1) / size
	}
	return out, nil
}

func (d *DB) count(ctx context.Context, f filterSQL, whereSQL string) (int, error) {
	countSQL := "SELECT COUNT(*) FROM agents" + f.joins + whereSQL
	var total int
	if err := d.db.QueryRowContext(ctx, countSQL, f.args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("sqlitestore: count: %w", err)
	}
	return total, nil
}

func (d *DB) queryAgents(ctx context.Context, query string, args []any) ([]domain.Agent, error) {
	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: search query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var items []domain.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlitestore: scan search row: %w", err)
		}
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlitestore: iterate search rows: %w", err)
	}
	return items, nil
}

func buildFilters(q port.SearchQuery) filterSQL {
	where := make([]string, 0)
	args := make([]any, 0)
	joins := ""
	ordered := " ORDER BY agents.display_name, agents.agent_id"

	if match := ftsMatch(q.Text); match != "" {
		joins = " JOIN agents_fts ON agents_fts.agent_id = agents.agent_id"
		where = append(where, "agents_fts MATCH ?")
		args = append(args, match)
		ordered = " ORDER BY agents_fts.rank, agents.agent_id"
	}

	add := func(clause string, a []any) {
		if clause != "" {
			where = append(where, clause)
			args = append(args, a...)
		}
	}
	clause, a := inClause("agents.status", statusStrings(q.Statuses))
	add(clause, a)
	clause, a = inClause("agents.provider_id", q.ProviderIDs)
	add(clause, a)
	clause, a = jsonAnyClause("agents.protocols", q.Protocols)
	add(clause, a)
	clause, a = jsonAnyClause("agents.transports", q.Transports)
	add(clause, a)
	clause, a = jsonAnyClause("agents.tags", q.Tags)
	add(clause, a)
	clause, a = jsonAnyClause("agents.capabilities", q.Capabilities)
	add(clause, a)
	clause, a = domainClause(q.AgentDomains)
	add(clause, a)

	return filterSQL{where: where, args: args, joins: joins, ordered: ordered}
}

// placeholders returns "?, ?, ..." for n binds (and "" for n<=0, since
// Repeat(0) yields ""). Callers only pass n>0.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func toAny(vals []string) []any {
	args := make([]any, len(vals))
	for i, v := range vals {
		args[i] = v
	}
	return args
}

// inClause builds `col IN (?, ?, ...)`. col is always a package constant.
func inClause(col string, vals []string) (string, []any) {
	if len(vals) == 0 {
		return "", nil
	}
	return col + " IN (" + placeholders(len(vals)) + ")", toAny(vals)
}

// jsonAnyClause matches rows whose JSON-array column contains any of vals.
func jsonAnyClause(col string, vals []string) (string, []any) {
	if len(vals) == 0 {
		return "", nil
	}
	return "EXISTS (SELECT 1 FROM json_each(" + col + ") je WHERE je.value IN (" + placeholders(len(vals)) + "))", toAny(vals)
}

// domainClause matches agents whose dns_name contains any of the given
// domains. LIKE special characters ('%', '_', '\\') in the caller-supplied
// value are escaped and an ESCAPE clause is set, so `?agentDomains=%` matches
// the literal '%' rather than every row.
func domainClause(vals []string) (string, []any) {
	if len(vals) == 0 {
		return "", nil
	}
	parts := make([]string, len(vals))
	args := make([]any, len(vals))
	for i, v := range vals {
		parts[i] = `agents.dns_name LIKE ? ESCAPE '\'`
		args[i] = "%" + escapeLike(v) + "%"
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

// escapeLike prefixes '%', '_' and '\\' with the '\\' ESCAPE character so the
// caller's string is matched literally under SQLite's LIKE.
func escapeLike(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	)
	return r.Replace(s)
}

func statusStrings(ss []domain.Status) []string {
	if len(ss) == 0 {
		return nil
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

// ftsMatch turns free-text into a safe FTS5 query: each whitespace-delimited
// term is double-quoted (escaping inner quotes) so punctuation in the input
// can't produce an FTS syntax error. Empty/whitespace input yields "".
func ftsMatch(text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	quoted := make([]string, len(fields))
	for i, f := range fields {
		quoted[i] = `"` + strings.ReplaceAll(f, `"`, `""`) + `"`
	}
	return strings.Join(quoted, " ")
}

func clampSize(size int) int {
	switch {
	case size <= 0:
		return defaultPageSize
	case size > maxPageSize:
		return maxPageSize
	default:
		return size
	}
}

// effectivePage resolves the 1-based page from PageToken (preferred, opaque) or
// the explicit Page, defaulting to 1 and clamping to maxPage.
func effectivePage(q port.SearchQuery) int {
	page := 1
	if q.PageToken != "" {
		if p, ok := decodeToken(q.PageToken); ok {
			page = p
		}
	} else if q.Page > 0 {
		page = q.Page
	}
	if page > maxPage {
		page = maxPage
	}
	return page
}

func encodeToken(page int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(tokenPrefix + strconv.Itoa(page)))
}

func decodeToken(tok string) (int, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return 0, false
	}
	s := string(raw)
	if !strings.HasPrefix(s, tokenPrefix) {
		return 0, false
	}
	p, err := strconv.Atoi(strings.TrimPrefix(s, tokenPrefix))
	if err != nil || p < 1 {
		return 0, false
	}
	return p, true
}
