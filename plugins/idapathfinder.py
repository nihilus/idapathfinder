import idc
import idaapi
import idautils
import pathfinder

class FunctionChooser(idaapi.Choose2):

	def __init__(self):
		idaapi.Choose2.__init__(self, "Choose a function", [["Function name", 50 | idaapi.Choose2.CHCOL_PLAIN]], icon=41)
		self.PopulateItems()

	def PopulateItems(self):
		self.items = [[idc.Name(f)] for f in idautils.Functions()]

	def OnGetLine(self, n):
		return self.items[n]

	def OnGetSize(self):
		return len(self.items)

	def OnClose(self):
		'''
		Although we don't use it, this MUST be defined or the chooser will never even be displayed by IDA.
		'''
		pass

	def GetUserInput(self):
		n = self.Show(modal=True)
		if n > -1:
			return self.items[n][0]
		else:
			return None


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

	def _find_and_plot_paths(self, sources, targets):
		results = []

		for target in targets:
			pf = pathfinder.PathFinder(target)
			for source in sources:
				results += pf.paths_from(source)
			del pf

		title = "Call graph from " + source
		if len(targets) == 1:
			title += " to " + target[0]

		g = pathfinder.PathFinderGraph(results, title)
		g.Show()
		del g

	def _get_user_selected_functions(self, many=False):
		functions = []

		fc = FunctionChooser()
		while True:
			function = fc.GetUserInput()
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

def PLUGIN_ENTRY():
	return idapathfinder_t()
