package workflow

type Diff struct {
	New     []string
	Removed []string
	Stable  []string
}

func ComputeDiff(oldHosts, newHosts []string) Diff {
	oldSet := map[string]struct{}{}
	newSet := map[string]struct{}{}
	for _, host := range oldHosts {
		oldSet[host] = struct{}{}
	}
	for _, host := range newHosts {
		newSet[host] = struct{}{}
	}

	result := Diff{}
	for _, host := range newHosts {
		if _, ok := oldSet[host]; ok {
			result.Stable = append(result.Stable, host)
		} else {
			result.New = append(result.New, host)
		}
	}
	for _, host := range oldHosts {
		if _, ok := newSet[host]; !ok {
			result.Removed = append(result.Removed, host)
		}
	}
	return result
}
