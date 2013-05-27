import idc
import idaapi
import idautils

class PathFinderGraph(idaapi.GraphViewer):
	'''
	Class for generating an idaapi.GraphViewer graph.
	'''

	def __init__(self, results, title="PathFinder Graph"):
		'''
		Class constructor.

		@results - A list of lists, each representing a call graph.
		@title   - The title of the graph window.

		Returns None.
		'''
		idaapi.GraphViewer.__init__(self, title)
		self.ids = {}
		self.nodes = {}
		self.history = []
		self.includes = []
		self.excludes = []
		self.end_nodes = []
		self.edge_nodes = []
		self.start_nodes = []
		self.delete_on_click = False
		self.include_on_click = False
		self.results = results
		self.activate_count = 0

	def Show(self):
		'''
		Display the graph.

		Returns True on success, False on failure.
		'''
		if not idaapi.GraphViewer.Show(self):
			return False
		else:
			# TODO: Add a colorize option to highlight all *displayed* nodes. Undo should undo the colorization as well.
			#       Or maybe colorization should be automatic, but removed when the window is closed?
			self.cmd_undo = self.AddCommand("Undo", "U")
			self.cmd_reset = self.AddCommand("Reset graph", "R")
			self.cmd_delete = self.AddCommand("Exclude node", "X")
			self.cmd_include = self.AddCommand("Include node", "I")
			self.activate_count = 0
			return True

	def OnRefresh(self):
		self.Clear()
		self.ids = {}
		self.nodes = {}
		self.end_nodes = []
		self.edge_nodes = []
		self.start_nodes = []

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
					self.start_nodes.append(path[0])
					self.end_nodes.append(path[-1])
					self.edge_nodes.append(path[-2])
				except:
					pass
	
		return True

	def OnActivate(self):
		if self.activate_count > 0:
			print "Refreshing due to activation...."
			self.Refresh()
		self.activate_count += 1

	def OnHint(self, node_id):
		return str(self[node_id])

	def OnGetText(self, node_id):
		node = str(self[node_id])

		if self.nodes[node_id] in self.edge_nodes:
			return (node, 0x00ffff)
		elif self.nodes[node_id] in self.start_nodes:
			return (node, 0x00ff00)
		elif self.nodes[node_id] in self.end_nodes:
			return (node, 0x0000ff)

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
	'''
	Base class for finding the path between two addresses.
	'''

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

	def _name2ea(self, nea):
		if isinstance(nea, type('')):
			return idc.LocByName(nea)
		return nea

	def paths_from(self, source, exclude=[], include=[], calls=[], nocalls=[]):
		'''
		Find paths from a source node to a destination node.

		@source  - The source node ea to start the search from.
		@exclude - A list of ea's to exclude from paths.
		@include - A list of ea's to include in paths.
		@calls   - A list of ea's that must be referenced from one of the path nodes.
		@nocalls - A list of ea's that must not be referenced from any of the path nodes.

		Returns a list of path lists.
		'''
		paths = []
		good_xrefs = []
		bad_xrefs = []

		source = self._name2ea(source)

		# If all the paths from the destination node have not already
		# been calculated, find them first before doing anything else.
		if not self.full_paths:
			self.find_paths(self.destination)

		for call in calls:
			call = self._name2ea(call)

			for xref in idautils.XrefsTo(call):
				f = idaapi.get_func(xref.frm)
				if f:
					good_xrefs.append(f.startEA)

		for call in nocalls:
			call = self._name2ea(call)

			for xref in idautils.XrefsTo(call):
				f = idaapi.get_func(xref.frm)
				if f:
					bad_xrefs.append(f.startEA)

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

				if good_xrefs:
					orig_index = index
					index = -1
					
					for xref in good_xrefs:
						if xref in p:
							index = orig_index

				if bad_xrefs:
					for xref in bad_xrefs:
						if xref in p:
							index = -1
							break

				if index > -1:
					# Be sure to include the destinatin and source nodes in the final path
					p = [self.destination] + p[:index+1]
					# The path is in reverse order (destination -> source), so flip it
					p = p[::-1]
					# Ignore any potential duplicate paths
					if p not in paths:
						paths.append(p)

		return paths

	def find_paths(self, ea, i=0):
		'''
		Performs a depth-first (aka, recursive) search to determine all possible call paths originating from the specified location.
		Called internally by self.paths_from.

		@ea - The start node to find a path from.
		@i  - Used to specify the recursion depth; for internal use only.

		Returns None.
		'''
		# Increment recursion depth counter by 1
		i += 1
		# Get the current call graph depth
		this_depth = self.depth

		# If this is the first level of recursion and the call
		# tree has not been built, then build it.
		if i == 1 and not self.tree:
			self.build_call_tree(ea)

		# Don't recurse past MAX_DEPTH	
		if i >= self.MAX_DEPTH:
			return

		# Loop through all the nodes in the call tree, starting at the specified location
		for (reference, children) in self.nodes[ea].iteritems():
			# Does this node have a reference that isn't already listed in our current call path?
			if reference and reference not in self.current_path:
				# Increase the call depth by 1
				self.depth += 1
				# Add the reference to the current path
				self.current_path.append(reference)
				# Find all paths from this new reference
				self.find_paths(reference, i)

		# If we didn't find any additional references to append to the current call path (i.e., this_depth == call depth)
		# then we have reached the limit of this call path.
		if self.depth == this_depth:
			# If the current call depth is not the same as the last recursive call, and if our list of paths
			# does not already contain the current path, then append a copy of the current path to the list of paths
			if self.last_depth != self.depth and self.current_path and self.current_path not in self.full_paths:
				self.full_paths.append(list(self.current_path))
			# Decrement the call path depth by 1 and pop the latest node out of the current call path
			self.depth -= 1
			if self.current_path:
				self.current_path.pop(-1)

		# Track the last call depth
		self.last_depth = self.depth	

	def build_call_tree(self, ea):
		'''
		Performs a breadth first (aka, iterative) search to build a call tree to the specified address.

		@ea - The node to generate a tree for.

		Returns None.
		'''
		self.tree[ea] = {}
		self.nodes[ea] = self.tree[ea]
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
		This must be overidden by a subclass to provide a list of xrefs.

		@node - The EA of the node that we need xrefs for.

		Returns a list of xrefs to the specified node.
		'''
		return []

class FunctionPathFinder(PathFinder):
	'''
	Subclass to generate paths between functions.
	'''

	def __init__(self, destination):
		func = idaapi.get_func(self._name2ea(destination))
		super(FunctionPathFinder, self).__init__(func.startEA)

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
	'''
	Subclass to generate paths between code blocks inside a function.
	'''

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

