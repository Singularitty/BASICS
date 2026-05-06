# Graphing library
import rustworkx as rx
from rustworkx.visualization import graphviz_draw
import os

# Module imports
from src.model_checker.models.memory_state import MemoryState

class StateSpace:
    
    def __init__(self, current_directory: str, binary_name: str):
        self.graph = rx.PyDiGraph(multigraph=False) # pylint: disable=no-member
        self.current_directory = current_directory
        self.binary_name = binary_name 
        self.state_space_images = None
        self._state_index_by_key = {}

    def _state_key(self, memory_state: MemoryState):
        frames = []
        for name, frame in sorted(memory_state.stack_frames_map.items()):
            frames.append((
                name,
                frame.stack_frame.tobytes(),
                tuple(sorted(frame.buffer_map.items())),
                frame.rbp,
                frame.canary,
                frame.canary_written,
            ))
        instruction_addr = None
        if memory_state.instruction is not None:
            instruction_addr = memory_state.instruction.address
        return tuple(frames), instruction_addr
        
    def add_state(self, memory_state: MemoryState):
        """
        Adds a memory state to the state space.
        """
        state_key = self._state_key(memory_state)
        if state_key in self._state_index_by_key:
            memory_state.index = self._state_index_by_key[state_key]
            return self.graph[memory_state.index]
        index = self.graph.add_node(memory_state)
        self.graph[index].index = index
        self._state_index_by_key[state_key] = index
        return self.graph[index]
        
    def add_transition(self, source_state: MemoryState, target_state: MemoryState, transition):
        """
        Adds a transition between two memory states.
        """
        source_index = source_state.index
        target_index = target_state.index
        index = self.graph.add_edge(source_index, target_index, transition)
        #self.graph[index].index = index
        
    def __node_attr_fn(self, node):
        representation = node.draw()
        return {
            "shape": 'record',
            "label": representation,
            "fontname" : "Courier",
            "style": "filled",
            "fillcolor": "lightblue"
            #"image": r"test" # use this in the future
        }
        
    def __edge_attr_fn(self, edge):
        return {
            "label": str(edge),
            "fontname" : "Courier"
            }
        
    def __graph_attr_fn(self):
        return {
            "rankdir": "LR",
            "fontname" : "Courier",
        }
        
    def draw(self):
        """
        Create an image of the state space.
        """
        graphviz_draw(self.graph, node_attr_fn=self.__node_attr_fn, edge_attr_fn=self.__edge_attr_fn, graph_attr=self.__graph_attr_fn(), image_type='pdf', filename=self.current_directory + "/reports/" + self.binary_name + "/state_space.pdf")
        
    def __draw_all_nodes(self):
        for node in self.graph.nodes():
            representation = node.draw()
            with open(self.state_space_images + f"/s{node.index}.dot", "w", encoding='utf8') as file:
                file.write(representation)
