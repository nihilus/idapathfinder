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
								"Find multiple paths from current function", 
								"Alt-6", 
								0, 
								self.FindPathsToMany, 
								(None,)))
		self.menu_contexts.append(idaapi.add_menu_item(ui_path, 
								"Find single path from current function", 
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

	def FindPathsToSingle(self, arg):
		source = self._current_function()

		if source:
			fc = FunctionChooser()
			target = fc.GetUserInput()
			if target:
				pf = pathfinder.PathFinder(target)
				results = pf.paths_from(source)
				del pf

				g = pathfinder.PathFinderGraph(results, "Call graph from " + source + " to " + target)
				g.Show()
				del g

	def FindPathsToMany(self, arg):
		targets = []
		results = []
		source = self._current_function()

		if source:
			fc = FunctionChooser()
			while True:
				target = fc.GetUserInput()
				if not target:
					break
				else:
					targets.append(target)

			if targets:
				for target in targets:
					pf = pathfinder.PathFinder(target)
					results += pf.paths_from(source)
					del pf

				g = pathfinder.PathFinderGraph(results, "Call graph from " + source)
				g.Show()
				del g

def PLUGIN_ENTRY():
	return idapathfinder_t()
