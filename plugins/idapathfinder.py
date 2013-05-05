import idc
import idaapi
import idautils
import pathfinder

class FunctionChooser(idaapi.Choose2):

	def __init__(self):
		idaapi.Choose2.__init__(self, "Choose a function", [["Function name", 50 | idaapi.Choose2.CHCOL_PLAIN]])
		self.icon = 41
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
		self.menu_context = idaapi.add_menu_item("View/Graphs/", "Find paths from current function", "Alt-5", 0, self.run, (None,))
		return idaapi.PLUGIN_KEEP

	def term(self):
		idaapi.del_menu_item(self.menu_context)
		return None
	
	def run(self, arg):
		source = GetFunctionName(ScreenEA())

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
		else:
			print "ERROR: Address 0x%X is not part of a defined function." % ea

def PLUGIN_ENTRY():
	return idapathfinder_t()
