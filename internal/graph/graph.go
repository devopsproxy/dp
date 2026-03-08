package graph

// NewGraph returns an empty, initialised Graph ready for use.
func NewGraph() *Graph {
	return &Graph{
		Nodes:   make(map[string]*Node),
		edgeSet: make(map[string]bool),
	}
}

// AddNode inserts node into the graph. If a node with the same ID already
// exists the call is a no-op (first write wins).
func (g *Graph) AddNode(node *Node) {
	if _, exists := g.Nodes[node.ID]; !exists {
		g.Nodes[node.ID] = node
	}
}

// AddEdge inserts a directed edge (from → to) of the given type.
// If the exact same (from, to, type) triple already exists the call is a no-op.
// Silently ignores edges whose from or to node IDs are not present in the graph.
func (g *Graph) AddEdge(from, to string, edgeType EdgeType) {
	if _, ok := g.Nodes[from]; !ok {
		return
	}
	if _, ok := g.Nodes[to]; !ok {
		return
	}
	key := from + "\x00" + to + "\x00" + string(edgeType)
	if g.edgeSet[key] {
		return
	}
	g.edgeSet[key] = true
	g.Edges = append(g.Edges, &Edge{From: from, To: to, Type: edgeType})
}

// GetNode returns the Node with the given ID, or nil if not found.
func (g *Graph) GetNode(id string) *Node {
	return g.Nodes[id]
}

// Neighbors returns all nodes that are direct successors of the node with the
// given ID (i.e. nodes reachable via one outgoing edge). Returns nil when the
// node has no outgoing edges or does not exist.
func (g *Graph) Neighbors(id string) []*Node {
	var result []*Node
	seen := make(map[string]bool)
	for _, e := range g.Edges {
		if e.From != id || seen[e.To] {
			continue
		}
		if n, ok := g.Nodes[e.To]; ok {
			result = append(result, n)
			seen[e.To] = true
		}
	}
	return result
}

// EdgesFrom returns all edges whose From field equals id.
func (g *Graph) EdgesFrom(id string) []*Edge {
	var result []*Edge
	for _, e := range g.Edges {
		if e.From == id {
			result = append(result, e)
		}
	}
	return result
}

// EdgesTo returns all edges whose To field equals id.
func (g *Graph) EdgesTo(id string) []*Edge {
	var result []*Edge
	for _, e := range g.Edges {
		if e.To == id {
			result = append(result, e)
		}
	}
	return result
}

// HasEdge reports whether a directed edge (from → to) of any type exists.
// This is an O(n) scan over the edge list intended for rendering use — for
// large graphs prefer EdgesFrom with a filtered search.
func (g *Graph) HasEdge(from, to string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}
