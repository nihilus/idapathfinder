import idc
import idaapi
import idautils
import pathfinder

class idapathfinder_t(idaapi.plugin_t):

	flags = 0
	comment = ''
	help = ''
	wanted_name = 'PathFinder'
	wanted_hotkey = ''

	def init(self):
		ui_path = "View/Graphs/"
		self.menu_contexts = []

		self.menu_contexts.append(idaapi.add_menu_item(ui_path,
								"Find paths to the current function block",
								"Alt-9",
								0,
								self.FindBlockPaths,
								(None,)))
		self.menu_contexts.append(idaapi.add_menu_item(ui_path,
								"Find paths from multiple functions to here",
								"Alt-8",
								0,
								self.FindPathsFromMany,
								(None,)))
		self.menu_contexts.append(idaapi.add_menu_item(ui_path,
								"Find paths from a single function to here",
								"Alt-7",
								0,
								self.FindPathsFromSingle,
								(None,)))
		self.menu_contexts.append(idaapi.add_menu_item(ui_path, 
								"Find paths from here to multiple functions", 
								"Alt-6", 
								0, 
								self.FindPathsToMany, 
								(None,)))
		self.menu_contexts.append(idaapi.add_menu_item(ui_path, 
								"Find paths from here to a single function", 
								"Alt-5", 
								0, 
								self.FindPathsToSingle, 
								(None,)))
		return idaapi.PLUGIN_KEEP

	def term(self):
		for context in self.menu_contexts:
			idaapi.del_menu_item(context)
		return None
	
	def run(self, arg):
		self.FindPathsToSingle()

	def _current_function(self):
		return GetFunctionName(ScreenEA())

	def _find_and_plot_paths(self, sources, targets, pfc=pathfinder.FunctionPathFinder):
		results = []

		for target in targets:
			pf = pfc(target)
			for source in sources:
				results += pf.paths_from(source)
			del pf

		title = "Call graph from " + source
		if len(targets) == 1:
			if isinstance(targets[0], type('')):
				title += " to " + targets[0]
			else:
				title += " to " + idc.GetFuncOffset(targets[0])

		g = pathfinder.PathFinderGraph(results, title)
		g.Show()
		del g

	def _get_user_selected_functions(self, many=False):
		functions = []

		while True:
			function = idc.Name(idc.ChooseFunction('Select a function'))
			if not function:
				break
			else:
				functions.append(function)

			if not many:
				break

		return functions
			
	def FindPathsToSingle(self, arg):
		source = self._current_function()

		if source:
			targets = self._get_user_selected_functions()
			if targets:
				self._find_and_plot_paths([source], targets)

	def FindPathsToMany(self, arg):
		source = self._current_function()

		if source:
			targets = self._get_user_selected_functions(many=True)
			if targets:
				self._find_and_plot_paths([source], targets)

	def FindPathsFromSingle(self, arg):
		target = self._current_function()

		if target:
			sources = self._get_user_selected_functions()
			if sources:
				self._find_and_plot_paths(sources, [target])

	def FindPathsFromMany(self, arg):
		target = self._current_function()

		if target:
			sources = self._get_user_selected_functions(many=True)
			if sources:
				self._find_and_plot_paths(sources, [target])

	def FindBlockPaths(self, arg):
		target = idc.ScreenEA()
		source = idc.GetFunctionName(idc.ScreenEA())
		self._find_and_plot_paths([source], [target], pfc=pathfinder.BlockPathFinder)

def PLUGIN_ENTRY():
	return idapathfinder_t()
