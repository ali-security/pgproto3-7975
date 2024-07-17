package sanitize

import (
    "fmt"
    "strings"
    "time"
)

type Query struct {
    Parts []Part
}

type Part interface{}

func (q *Query) Sanitize(args ...any) (string, error) {
    if len(args) != len(q.Parts)-1 {
        return "", fmt.Errorf("invalid number of arguments: %d instead of %d", len(args), len(q.Parts)-1)
    }

    var builder strings.Builder
    argIdx := 0
    argUse := map[int]bool{}

    for _, part := range q.Parts {
        switch partTyped := part.(type) {
        case string:
            builder.WriteString(partTyped)
        case int:
            if argIdx >= len(args) {
                return "", fmt.Errorf("unexpected argument index: %d", argIdx)
            }
            arg, ok := args[partTyped].(string)
            if !ok {
                return "", fmt.Errorf("invalid arg type: %T", args[partTyped])
            }
            builder.WriteString(arg)
            argUse[partTyped] = true
        case int64, float64, bool, []byte, nil, time.Time:
            if argIdx >= len(args) {
                return "", fmt.Errorf("unexpected argument index: %d", argIdx)
            }
            arg := args[argIdx]
            var str string
            switch argTyped := arg.(type) {
            case int64:
                str = fmt.Sprintf("%d", argTyped)
            case float64:
                str = fmt.Sprintf("%f", argTyped)
            case bool:
                str = fmt.Sprintf("%t", argTyped)
            case []byte:
                str = fmt.Sprintf("'%s'", argTyped)
            case nil:
                str = "null"
            case time.Time:
                str = fmt.Sprintf("'%s'", argTyped.Format(time.RFC3339Nano))
            default:
                return "", fmt.Errorf("invalid arg type: %T", arg)
            }
            argUse[argIdx] = true

            // Prevent SQL injection via Line Comment Creation
            // https://github.com/jackc/pgx/security/advisories/GHSA-m7wr-2xf7-cm9p
            str = "(" + str + ")"
            builder.WriteString(str)
        default:
            return "", fmt.Errorf("invalid Part type: %T", part)
        }
        argIdx++
    }

    for argIdx := range args {
        if !argUse[argIdx] {
            return "", fmt.Errorf("argument %d was not used", argIdx)
        }
    }

    return builder.String(), nil
}
