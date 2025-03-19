package conftamer

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
)

// Write behavior map to csv - unsure how to get rid of extra quotes (part of the RFC)
func WriteBehaviorMap(filename string, behavior_map BehaviorMap) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	w := csv.NewWriter(file)
	w.Write([]string{"Behavior", "Tainting Values"})

	for key, value := range behavior_map {
		key_bytes, err := json.Marshal(key)
		if err != nil {
			return err
		}

		value_bytes, err := json.Marshal(&value)
		if err != nil {
			return err
		}
		err = w.Write([]string{string(key_bytes), string(value_bytes)})
		if err != nil {
			return err
		}
	}

	w.Flush()
	return nil
}

// Read behavior map from csv
func ReadBehaviorMap(filename string) (BehaviorMap, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	r := csv.NewReader(file)

	if _, err := r.Read(); err != nil { // read header
		return nil, err
	}
	behavior_map := make(BehaviorMap)

	for {
		row, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
		behavior_value := BehaviorValue{}
		tainting_vals := newTaintingVals()

		for i, col := range row {
			if i == 0 {
				err := json.Unmarshal([]byte(col), &behavior_value)
				if err != nil {
					return nil, err
				}
			} else {
				err := json.Unmarshal([]byte(col), &tainting_vals)
				if err != nil {
					return nil, err
				}
			}
		}

		behavior_map[behavior_value] = tainting_vals
	}
	return behavior_map, nil
}
