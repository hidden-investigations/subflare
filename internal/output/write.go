package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hidden-investigations/subflare/internal/model"
)

func WriteText(path string, results []model.Result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, result := range results {
		if _, err := fmt.Fprintln(writer, result.Host); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func WriteJSONL(path string, results []model.Result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			return err
		}
	}
	return writer.Flush()
}
