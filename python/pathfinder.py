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
				prev_func = None

				for func in path:
					if not self.ids.has_key(func):
						self.ids[func] = self.AddNode(func)
						self.nodes[self.ids[func]] = func
					if prev_func is not None:
						self.AddEdge(prev_func, self.ids[func])
					prev_func = self.ids[func]

				try:
					self.edge_nodes.append(path[-2])
				except:
					pass
	
		return True

	def OnGetText(self, node_id):
		node = str(self[node_id])
		if node in self.edge_nodes:
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
		idc.Jump(self._node_offset(node_id))

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

	def _node_offset(self, node_id):
		delim = None
		loc = idc.BADADDR
		func_off_delims = [':', '+']

		for d in func_off_delims:
			if d in self.nodes[node_id]:
				delim = d
				break

		if delim:
			(function_name, offset_str) = self.nodes[node_id].split(delim, 1)
			loc = idc.LocByName(function_name)
			try:
				loc += int(offset_str, 16)
			except:
				try:
					loc += int(offset_str, 10)
				except:
					# TODO: This doesn't work, especially when the location offset string is a custom name 
					# (e.g., there may be other nodes in other functions named 'end')
					loc_name_offset = idc.LocByName(offset_str)
					if loc_name_offset != idc.BADADDR:
						loc += loc_name_offset
		else:
			loc = idc.LocByName(self.nodes[node_id])

		return loc

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

		@destination - The end node name.

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

		@source  - The source node to start the search from.
		@exclude - A list of function names to exclude from paths.
		@include - A list of function names to include in paths.

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

	def find_paths(self, name, i=0):
		'''
		Finds all paths from the destination to the specified name.
		Called internally by self.paths_from.

		@name - The start node to find a path from.
		@i    - Used to specify the recursion depth; for internal use only.

		Returns None.
		'''
		i += 1
		this_depth = self.depth

		if i == 1 and not self.tree:
			self.build_call_tree(name)
		
		if i >= self.MAX_DEPTH:
			return

		for (reference, children) in self.nodes[name].iteritems():
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

	def build_call_tree(self, name):
		'''
		Builds a call tree to a named function.

		@name - The function name to generate a tree for.

		Returns None.
		'''
		tree_ptr = self.tree

		tree_ptr[name] = {}
		self.nodes[name] = tree_ptr[name]
		names = [name]

		while names:
			new_names = []

			for name in names:
				if name:
					name_node = self.nodes[name]

					for reference in self.node_xrefs(name):
						if reference not in self.nodes:
							name_node[reference] = {}
							self.nodes[reference] = name_node[reference]
							new_names.append(reference)
						elif not name_node.has_key(reference):
							name_node[reference] = self.nodes[reference]
			
			names = new_names

class FunctionPathFinder(PathFinder):

	def node_xrefs(self, name):
		return [idc.GetFunctionName(x.frm) for x in idautils.XrefsTo(idc.LocByName(name)) if x.type != 21]

class BlockPathFinder(PathFinder):

	def __init__(self, ea):
		f = idaapi.get_func(ea)
		self.blocks = idaapi.FlowChart(f=f)
		
		self.source_ea = f.startEA
		self.source_name = idc.GetFunctionName(f.startEA)
		self.destination = self.LookupBlock(ea=ea)
		
		super(BlockPathFinder, self).__init__(idc.GetFuncOffset(self.destination.startEA))

	def LookupBlock(self, name=None, ea=idc.BADADDR):
		retblock = None

		for block in self.blocks:
			if name and idc.GetFuncOffset(block.startEA) == name:
				retblock = block
			elif ea != idc.BADADDR and ea >= block.startEA and ea <= block.endEA:
				retblock = block

		return retblock
		
	def node_xrefs(self, name):
		xrefs = []
		block = self.LookupBlock(name)

		if block and name != self.source_name and block.startEA != self.source_ea:
			for xref in idautils.XrefsTo(block.startEA):
				xref_block = self.LookupBlock(ea=xref.frm)
				if xref_block:
					xref_name = idc.GetFuncOffset(xref_block.startEA)
					xrefs.append(xref_name)

		return xrefs

