import idc
import idaapi
import idautils

class PathFinderGraph(idaapi.GraphViewer):

	def __init__(self, results, title="PathFinder Graph"):
		idaapi.GraphViewer.__init__(self, title)
		self.ids = {}
		self.nodes = {}
		self.history = []
		self.includes = []
		self.excludes = []
		self.edge_nodes = []
		self.delete_on_click = False
		self.include_on_click = False
		self.results = results

	def OnRefresh(self):
		self.Clear()
		self.ids = {}
		self.nodes = {}

		for path in self.results:
			nogo = False

			for include in self.includes:
				if include not in path:
					nogo = True

			for exclude in self.excludes:
				if exclude in path:
					nogo = True
					break
	
			if not nogo:
				prev_node = None

				for node in path:
					name = self.get_node_name(node)

					if not self.ids.has_key(name):
						self.ids[name] = self.AddNode(name)
						self.nodes[self.ids[name]] = node
					if prev_node is not None:
						self.AddEdge(prev_node, self.ids[name])
					prev_node = self.ids[name]

				try:
					self.edge_nodes.append(path[-2])
				except:
					pass
	
		return True

	def OnGetText(self, node_id):
		node = str(self[node_id])
		if self.nodes[node_id] in self.edge_nodes:
			return (node, 0xff00f0)
		return node

	def OnCommand(self, cmd_id):
		if self.cmd_undo == cmd_id:
			self._undo()
		elif self.cmd_include == cmd_id:
			self.include_on_click = True
		elif self.cmd_delete == cmd_id:
			self.delete_on_click = True
		elif self.cmd_reset == cmd_id:
			self._reset()

	def OnDblClick(self, node_id):
		idc.Jump(self.nodes[node_id])

	def OnClick(self, node_id):
		if self.delete_on_click:
			self.delete_on_click = False
			self.excludes.append(self.nodes[node_id])
			self.history.append('exclude')
		elif self.include_on_click:
			self.include_on_click = False
			self.includes.append(self.nodes[node_id])
			self.history.append('include')
		self.Refresh()

	def Show(self):
		if not idaapi.GraphViewer.Show(self):
			return False
		else:
			# TODO: Add a colorize option to highlight all *displayed* nodes. Undo should undo the colorization as well.
			#       Or maybe colorization should be automatic, but removed when the window is closed?
			self.cmd_undo = self.AddCommand("Undo", "U")
			self.cmd_reset = self.AddCommand("Reset graph", "R")
			self.cmd_delete = self.AddCommand("Exclude node", "X")
			self.cmd_include = self.AddCommand("Include node", "I")
			return True

	def get_node_name(self, ea):
		name = idc.Name(ea)
		if not name:
			name = idc.GetFuncOffset(ea)
			if not name:
				name = "0x%X" % ea
		return name

	def _undo(self):
		self.delete_on_click = False
		self.include_on_click = False
		
		if self.history:
			last_action = self.history.pop(-1)
		else:
			last_action = None

		if last_action == 'include' and self.includes:
			self.includes.pop(-1)
		elif last_action == 'exclude' and self.excludes:
			self.excludes.pop(-1)
			
		self.Refresh()

	def _reset(self):
		self.history = []
		self.includes = []
		self.excludes = []
		self.delete_on_click = False
		self.include_on_click = False
		self.Refresh()

class PathFinder(object):

	# Limit the max recursion depth
	MAX_DEPTH = 500

	def __init__(self, destination):
		'''
		Class constructor.

		@destination - The end node ea.

		Returns None.
		'''
		self.tree = {}
		self.nodes = {}
		self.depth = 0
		self.last_depth = 0
		self.full_paths = []
		self.current_path = []
		self.destination = destination
		self.build_call_tree(self.destination)

	def __enter__(self):
		return self
		
	def __exit__(self, t, v, traceback):
		return

	def paths_from(self, source, exclude=[], include=[]):
		'''
		Find paths from a source node to a destination node.

		@source  - The source node ea to start the search from.
		@exclude - A list of ea's to exclude from paths.
		@include - A list of ea's to include in paths.

		Returns a list of path lists.
		'''
		paths = []

		if not self.full_paths:
			self.find_paths(self.destination)

		for p in self.full_paths:
			if source in p:
				index = p.index(source)

				if exclude:
					for ex in excludes:
						if ex in p:
							index = -1
							break
				
				if include:
					orig_index = index
					index = -1

					for inc in include:
						if inc in p:
							index = orig_index
							break

				if index > -1:
					p = [self.destination] + p[:index+1]
					p = p[::-1]
					if p not in paths:
						paths.append(p)

		return paths

	def find_paths(self, ea, i=0):
		'''
		Finds all paths from the destination to the specified name.
		Called internally by self.paths_from.

		@ea - The start node to find a path from.
		@i  - Used to specify the recursion depth; for internal use only.

		Returns None.
		'''
		i += 1
		this_depth = self.depth

		if i == 1 and not self.tree:
			self.build_call_tree(ea)
	
		if i >= self.MAX_DEPTH:
			return

		for (reference, children) in self.nodes[ea].iteritems():
			if reference and reference not in self.current_path:
				self.depth += 1
				self.current_path.append(reference)
				self.find_paths(reference, i)

		if self.depth == this_depth:
			if self.last_depth != self.depth and self.current_path and self.current_path not in self.full_paths:
				self.full_paths.append(list(self.current_path))
			self.depth -= 1
			if self.current_path:
				self.current_path.pop(-1)

		self.last_depth = self.depth	

	def build_call_tree(self, ea):
		'''
		Builds a call tree to a named function.

		@ea - The node to generate a tree for.

		Returns None.
		'''
		tree_ptr = self.tree

		tree_ptr[ea] = {}
		self.nodes[ea] = tree_ptr[ea]
		nodes = [ea]

		while nodes:
			new_nodes = []

			for node in nodes:
				if node and node != idc.BADADDR:
					node_ptr = self.nodes[node]

					for reference in self.node_xrefs(node):
						if reference not in self.nodes:
							node_ptr[reference] = {}
							self.nodes[reference] = node_ptr[reference]
							new_nodes.append(reference)
						elif not node_ptr.has_key(reference):
							node_ptr[reference] = self.nodes[reference]
			
			nodes = new_nodes

	def node_xrefs(self, node):
		'''
		This must be overidden by the subclass to provide a list of xrefs.

		@node - The EA of the node that we need xrefs for.

		Returns a list of xrefs to the specified node.
		'''
		return []

class FunctionPathFinder(PathFinder):

	def node_xrefs(self, node):
		'''
		Return a list of function EA's that reference the given node.
		'''
		xrefs = []

		for x in idautils.XrefsTo(node):
			if x.type != idaapi.fl_F:
				f = idaapi.get_func(x.frm)
				if f and f.startEA not in xrefs:
					xrefs.append(f.startEA)
		return xrefs

class BlockPathFinder(PathFinder):

	def __init__(self, destination):
		func = idaapi.get_func(destination)
		self.blocks = idaapi.FlowChart(f=func)
	
		self.source_ea = func.startEA
		dst_block = self.LookupBlock(destination)

		if dst_block:
			super(BlockPathFinder, self).__init__(dst_block.startEA)

	def LookupBlock(self, ea):
		for block in self.blocks:
			if ea >= block.startEA and ea < block.endEA:
				return block
		return None
		
	def node_xrefs(self, node):
		'''
		Return a list of blocks that reference the provided block.
		'''
		xrefs = []

		block = self.LookupBlock(node)
		if block:
			for xref in idautils.XrefsTo(block.startEA):
				xref_block = self.LookupBlock(xref.frm)
				if xref_block and xref_block.startEA not in xrefs:
					xrefs.append(xref_block.startEA)
		return xrefs

