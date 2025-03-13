package conftamer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	set "github.com/hashicorp/go-set"
)

type EventType string

const (
	MessageSend       EventType = "Message send"
	MessageRecv       EventType = "Message receive"
	WatchpointHit     EventType = "Watchpoint hit"
	WatchpointSet     EventType = "Watchpoint set"
	MemParamMapUpdate EventType = "Mem-param map update"
	BehaviorMapUpdate EventType = "Behavior map update"
)

// A row of the event log, for the columns that test will check
// (so excludes e.g. timestamp)
type Event struct {
	EventType EventType
	// Address of memory region
	// Unused for BehaviorMapUpdate
	Address uint64
	// Size of memory region
	// Used for all (always 1 for map updates, since entries are per byte)
	Size uint64
	// Only used for WatchpointHit/WatchpointSet
	Expression string
	// Only used for MessageSend/MessageRecv and BehaviorMapUpdate (for behavior map, is key)
	// For MessageSend/MessageRecv, offset is 0
	Behavior *BehaviorValue
	// Only used for MemParamMapUpdate/BehaviorMapUpdate
	TaintingVals *TaintingVals
	Line         int // Filled in on read from csv
}

// Also used in test to print events
func WriteEvent(tc *TaintCheck, w *csv.Writer, e Event) {
	behavior := []byte{}
	var err error
	if e.Behavior != nil {
		behavior, err = json.Marshal(e.Behavior)
		if err != nil {
			log.Fatalf("marshaling %v: %v\n", behavior, err.Error())
		}
	}
	tainting_vals := []byte{}
	if e.TaintingVals != nil {
		tainting_vals, err = json.Marshal(e.TaintingVals)
		if err != nil {
			log.Fatalf("marshaling %v: %v\n", e.TaintingVals, err.Error())
		}
	}
	var loc, goroutine string
	if tc != nil {
		file, line, addr := tc.hitLocation()
		loc = fmt.Sprintf("%v %v %#x", file, line, addr)
		goroutine = fmt.Sprintf("thread %v goroutine %v", tc.thread.ID, tc.thread.GoroutineID)
	}
	row := []string{string(e.EventType), fmt.Sprintf("%#x", e.Address), fmt.Sprintf("%#x", e.Size), e.Expression,
		string(behavior), string(tainting_vals), time.Now().String(), loc, goroutine}

	if err := w.WriteAll([][]string{row}); err != nil {
		log.Fatalf("writing event %v: %v\n", row, err.Error())
	}
}

func ReadEventLog(filename string) ([]Event, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	r := csv.NewReader(file)

	if _, err := r.Read(); err != nil { // read header
		return nil, err
	}
	events := []Event{}

	for {
		row, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
		e := Event{}
		e.EventType = EventType(row[0])
		behavior_value := BehaviorValue{}
		tainting_vals := TaintingVals{Params: *set.New[TaintingParam](0), Behaviors: *set.New[TaintingBehavior](0)}

		for i, col := range row[1:3] {
			num, err := strconv.ParseUint(col, 0, 64)
			if err != nil {
				return events, err
			}
			if i == 0 {
				e.Address = num
			} else {
				e.Size = num
			}
		}
		e.Expression = row[3]

		if row[4] != "" {
			err := json.Unmarshal([]byte(row[4]), &behavior_value)
			if err != nil {
				return events, err
			}
			e.Behavior = &behavior_value
		}
		if row[5] != "" {
			err := json.Unmarshal([]byte(row[5]), &tainting_vals)
			if err != nil {
				return events, err
			}
			e.TaintingVals = &tainting_vals
		}

		line, err := strconv.Atoi(strings.Split(row[7], " ")[1])
		if err != nil {
			return events, err
		}
		e.Line = line

		events = append(events, e)
		// ignore timestamp for now
	}
	return events, nil
}
