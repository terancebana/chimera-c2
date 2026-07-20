package main

import "testing"

func TestBufferChunkReassembly(t *testing.T) {
	cases := []struct {
		name  string
		parts []string
		order []int // index sent each call
	}{
		{"single", []string{"ABCDE"}, []int{0}},
		{"three_in_order", []string{"AAA", "BBB", "CCC"}, []int{0, 1, 2}},
		{"three_out_of_order", []string{"AAA", "BBB", "CCC"}, []int{2, 0, 1}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// ensure clean state
			chunkMu.Lock()
			delete(chunkBuffers, c.name)
			chunkMu.Unlock()

			var got string
			var complete bool
			for _, idx := range c.order {
				complete, got = bufferChunk(c.name, c.parts[idx], idx, len(c.parts))
			}
			if !complete {
				t.Fatalf("expected complete after all chunks; got complete=%v", complete)
			}
			want := ""
			for _, p := range c.parts {
				want += p
			}
			if got != want {
				t.Fatalf("reassembly mismatch: got %q want %q", got, want)
			}
		})
	}
}

func TestBufferChunkPartial(t *testing.T) {
	const agent = "partial-agent"
	chunkMu.Lock()
	delete(chunkBuffers, agent)
	chunkMu.Unlock()

	complete, _ := bufferChunk(agent, "AAA", 0, 3)
	if complete {
		t.Fatal("should not be complete after first of three chunks")
	}
	complete, _ = bufferChunk(agent, "BBB", 1, 3)
	if complete {
		t.Fatal("should not be complete after two of three chunks")
	}
	complete, full := bufferChunk(agent, "CCC", 2, 3)
	if !complete {
		t.Fatal("should be complete after final chunk")
	}
	if full != "AAABBBCCC" {
		t.Fatalf("unexpected reassembled body: %q", full)
	}
}
