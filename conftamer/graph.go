package conftamer

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
)

type NodeType string

const (
	Parameter NodeType = "configuration parameter"
	Behavior  NodeType = "behavior"
)

const EdgeType = "EdgeType"

type Node struct {
	NodeType  NodeType
	Parameter Param
	Behavior  BehaviorValue
}

// To help typecheck (some graph functions take hashes, other nodes)
type NodeHashType Node

func NodeHash(n Node) NodeHashType {
	// Ignore send/recv modules - not needed to uniquely id node,
	// and allows searching for other party's copy
	return NodeHashType{
		Parameter: n.Parameter,
		Behavior: BehaviorValue{
			Offset:        n.Behavior.Offset,
			Behavior_type: n.Behavior.Behavior_type,
			Network_msg:   n.Behavior.Network_msg,
			Function_arg:  n.Behavior.Function_arg,
		},
	}
}

func AddBehaviorNode(g graph.Graph[NodeHashType, Node], n Node) error {
	other_node, err := g.Vertex(NodeHash(n))
	if err == nil {
		// found => combine its module info with existing
		if n.Behavior.Send_module == "" {
			n.Behavior.Send_module = other_node.Behavior.Send_module
		}
		if n.Behavior.Recv_module == "" {
			n.Behavior.Recv_module = other_node.Behavior.Recv_module
		}
		if err := g.UpdateVertex(NodeHash(n), n); err != nil {
			return fmt.Errorf("update vertex for behavior node %+v: %v", n, err)
		}
	} else {
		if err := g.AddVertex(n); err != nil {
			return fmt.Errorf("failed to add behavior node %+v that didn't exist: %v", n, err)
		}
	}
	return nil
}

// Remove any nodes not reachable from roots - these exist because
// we treat all received messages as tainted.
// Note any vertex/edge properties must be passed in to new graph
func RemoveUnreachableNodes(g graph.Graph[NodeHashType, Node], roots []Node) (graph.Graph[NodeHashType, Node], error) {
	adjacencyMap, err := g.AdjacencyMap() // node => {neighbor, edge}
	if err != nil {
		return nil, err
	}

	g_new := graph.New(NodeHash, graph.Directed())
	// DFS only traverses nodes reachable from start => add those to a new graph
	for _, root := range roots {
		_ = g_new.AddVertex(root)
		err := graph.DFS(g, NodeHash(root), func(cur_hash NodeHashType) bool {
			// Add neighbors to new graph
			neighbors := adjacencyMap[cur_hash]
			for neighbor_hash, edge := range neighbors {
				neighbor, err := g.Vertex(neighbor_hash)
				if err != nil {
					log.Panicf("Neighbor %+v not found: %v\n", neighbor_hash, err)
				}
				if err := g_new.AddVertex(neighbor); err != nil && !errors.Is(err, graph.ErrVertexAlreadyExists) {
					log.Panicf("Adding neighbor %+v: %v", neighbor, err)
				}

				err = g_new.AddEdge(cur_hash, neighbor_hash, graph.EdgeAttributes(edge.Properties.Attributes))
				if err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
					log.Panicf("Error adding edge %+v => %+v: %v\n", cur_hash, neighbor_hash, err.Error())
				}
			}
			return false // means continue traversing
		})

		if err != nil {
			return nil, err
		}
	}

	return g_new, nil
}

// Assemble behavior_maps into a single in-memory graph, return graph and write it to a .gv
func WriteGraph(outfile string, behavior_map_files []string) (graph.Graph[NodeHashType, Node], error) {
	g := graph.New(NodeHash, graph.Directed())
	roots := []Node{}

	// 1. Add nodes across all behavior maps, combining sent and received
	for _, behavior_map_file := range behavior_map_files {
		behavior_map, err := ReadBehaviorMap(behavior_map_file)
		if err != nil {
			return nil, fmt.Errorf("reading behavior map file %v: %v", behavior_map_file, err.Error())
		}
		for behavior, tainting_vals := range behavior_map {
			tainted_by := Node{NodeType: Behavior, Behavior: behavior}
			if err := AddBehaviorNode(g, tainted_by); err != nil {
				return nil, err
			}

			tainting_vals.Params.ForEach(func(tp TaintingParam) bool {
				taints := Node{NodeType: Parameter, Parameter: tp.Param}
				roots = append(roots, taints)
				_ = g.AddVertex(taints)
				err := g.AddEdge(NodeHash(taints), NodeHash(tainted_by), graph.EdgeAttribute(EdgeType, string(tp.Flow)))
				if err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
					// XXX same val can taint a behavior by both data and control flow (see control_flow test) - handle here
					log.Panicf("Error adding edge %+v => %+v: %v\n", taints, tainted_by, err.Error())
				}
				return true
			})

			tainting_vals.Behaviors.ForEach(func(tb TaintingBehavior) bool {
				taints := Node{NodeType: Behavior, Behavior: tb.Behavior}
				if err := AddBehaviorNode(g, taints); err != nil {
					log.Panicf("Adding behavior node %+v: %v\n", taints, err)
				}
				err := g.AddEdge(NodeHash(taints), NodeHash(tainted_by), graph.EdgeAttribute(EdgeType, string(tb.Flow)))
				if err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
					log.Panicf("Error adding edge %+v => %+v: %v\n", taints, tainted_by, err.Error())
				}
				return true
			})
		}
	}

	// 2. Remove unreachable nodes from the full graph
	var err error
	g, err = RemoveUnreachableNodes(g, roots)
	if err != nil {
		return nil, err
	}
	file, err := os.Create(outfile)
	if err != nil {
		return nil, fmt.Errorf("creating graph file %v: %v", file, err.Error())
	}
	if err := draw.DOT(g, file); err != nil {
		return nil, fmt.Errorf("drawing graph to %v: %v", file, err.Error())
	}
	return g, nil
}
