import idc
import idaapi
import idautils

class PathFinderGraph(idaapi.GraphViewer):

	def __init__(self, results, title):
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
		idc.Jump(idc.LocByName(self.nodes[node_id]))

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
			self.cmd_undo = self.AddCommand("Undo", "U")
			self.cmd_reset = self.AddCommand("Reset graph", "R")
			self.cmd_delete = self.AddCommand("Exclude node", "X")
			self.cmd_include = self.AddCommand("Include node", "I")
			return True

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

					for reference in [idc.GetFunctionName(x.frm) for x in idautils.XrefsTo(idc.LocByName(name)) if x.type != 21]:
						if reference not in self.nodes:
							name_node[reference] = {}
							self.nodes[reference] = name_node[reference]
							new_names.append(reference)
						elif not name_node.has_key(reference):
							name_node[reference] = self.nodes[reference]
			
			names = new_names

