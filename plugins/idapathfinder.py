import idc
import idaapi
import idautils
import pathfinder

class PathFinderGraph(idaapi.GraphViewer):

	def __init__(self, frm, to, results):
		idaapi.GraphViewer.__init__(self, "Call graph from " + frm + " to " + to)
		self.ids = {}
		self.nodes = {}
		self.include = ''
		self.history = []
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

			if self.include and self.include not in path:
				continue

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
		elif self.include_on_click and not self.include:
			self.include_on_click = False
			self.include = self.nodes[node_id]
			self.history.append('include')
		self.Refresh()

	def Show(self):
		if not idaapi.GraphViewer.Show(self):
			return False
		else:
			self.cmd_undo = self.AddCommand("Undo", "U")
			self.cmd_reset = self.AddCommand("Reset graph", "R")
			self.cmd_delete = self.AddCommand("Delete node", "D")
			self.cmd_include = self.AddCommand("Include node", "I")
			return True

	def _undo(self):
		self.delete_on_click = False
		self.include_on_click = False
		
		if self.history:
			last_action = self.history[-1]
		else:
			last_action = None

		if last_action == 'include':
			self.include = ''
		elif self.excludes:
			self.excludes.pop(-1)
			
		if self.history:
			self.history.pop(-1)

		self.Refresh()

	def _reset(self):
		self.include = ''
		self.history = []
		self.excludes = []
		self.delete_on_click = False
		self.include_on_click = False
		self.Refresh()


class idapathfinder_t(idaapi.plugin_t):

	flags = 0
	comment = ''
	help = ''
	wanted_name = 'PathFinder'
	wanted_hotkey = ''

	def init(self):
		self.menu_context = idaapi.add_menu_item("View/Graphs/", "Find all paths to...", "Alt-5", 0, self.run, (None,))
		return idaapi.PLUGIN_KEEP

	def term(self):
		idaapi.del_menu_item(self.menu_context)
		return None
	
	def run(self, arg):
		source = GetFunctionName(ScreenEA())
		if source:
			target = AskIdent(source, 'Find paths to')
			if target:
				pf = pathfinder.PathFinder(target)
				results = pf.paths_from(source)
				del pf

				g = PathFinderGraph(source, target, results)
				g.Show()
				del g

def PLUGIN_ENTRY():
	return idapathfinder_t()

