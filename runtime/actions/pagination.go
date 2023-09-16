package actions

import (
	"fmt"
	"strconv"

	q "github.com/teamkeel/keel/query"
)

// ParsePage extracts page mandate information from the given map and uses it to
// compose a Page.
func ParsePage(args map[string]any) (q.Page, error) {
	page := q.Page{}

	if first, ok := args["first"]; ok {
		switch v := first.(type) {
		case int64:
			page.First = int(v)
		case int:
			page.First = v
		case float64:
			page.First = int(v)
		case string:
			num, err := strconv.Atoi(v)

			if err == nil {
				page.First = num
			}
		}
	}

	if last, ok := args["last"]; ok {
		switch v := last.(type) {
		case int64:
			page.Last = int(v)
		case float64:
			page.Last = int(v)
		case int:
			page.Last = v
		case string:
			num, err := strconv.Atoi(v)

			if err == nil {
				page.Last = num
			}
		}
	}

	// If none specified - use a sensible default
	if page.First == 0 && page.Last == 0 {
		page.First = 50
	}

	if after, ok := args["after"]; ok {
		asString, ok := after.(string)
		if !ok {
			return page, fmt.Errorf("cannot cast this: %v to a string", after)
		}
		page.After = asString
	}

	if before, ok := args["before"]; ok {
		asString, ok := before.(string)
		if !ok {
			return page, fmt.Errorf("cannot cast this: %v to a string", before)
		}
		page.Before = asString
	}

	return page, nil
}
