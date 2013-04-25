import idc
import idautils

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

