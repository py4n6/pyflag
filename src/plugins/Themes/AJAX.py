""" An AJAX based theme """
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry
import pyflag.Theme as Theme
import pyflag.DB as DB
from plugins.Themes.Menus import Menu

class AJAX(Menu):
    header='''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
        <html>
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>%s</title>
        <link rel="stylesheet" type="text/css" href="images/ajax_ui.css" />
        <script type="text/javascript">
        var djConfig = { isDebug: true, baseScriptUri: "/javascript/", debugAtAllCosts: false };
        </script>
        <script type="text/javascript" src="/javascript/dojo.js"></script>
 
        <script type="text/javascript">
        dojo.require("dojo.widget.ComboBox");
        dojo.require("dojo.widget.SplitContainer");
        dojo.require("dojo.widget.ContentPane");
        dojo.require("dojo.widget.TabContainer");
        dojo.require("dojo.widget.LinkPane");
        dojo.require("dojo.widget.LayoutContainer");
        dojo.require("dojo.widget.Tree");
        dojo.require("dojo.widget.TreeSelector");
        dojo.require("dojo.widget.TreeLoadingController");
        dojo.require("dojo.widget.Menu2");
        dojo.require("dojo.widget.Button");
        dojo.require("dojo.widget.Dialog");
        dojo.require("dojo.widget.Toolbar");
        dojo.require("dojo.widget.FloatingPane");
        dojo.require("dojo.widget.Tooltip");
        dojo.require("dojo.widget.DropdownDatePicker");
        dojo.require("dojo.widget.RichText");
        dojo.require("dojo.uri.Uri");
        dojo.require("dojo.collections.Stack");
        dojo.hostenv.writeIncludes();

        </script>
        <script type="text/javascript" src="/javascript/ajax_misc.js"></script>
        
        </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF">
        
        <div dojoType="dialog" id="FilterDialog" bgColor="white" bgOpacity="0.5" toggle="fade" toggleDuration="250">
	<form action="javascript:update_filter_column();">
		<table>
                        <th><td colspan="2" align="left">Search Column <span id="search_name"></span></td></th>
			<tr>
				<td>Search expression:</td>
				<td><input type="text" id="search_expression"></td>
			</tr>
			<tr>
				<td align="left" colspan="2">
					<input type="button" id="search_ok" value="OK" onClick="update_filter_column();"><input type="button" id="search_cancel" value="Cancel" onClick="return false;"></td>
			</tr>
		</table>
	</form>
</div>
        '''

    footer="\n</div></div></body></html>"
    def make_menu_javascript(self,query):
        """ Creates the javascript required to generate the menu """
        ## Find all families:
        module_list = Registry.REPORTS.get_families()
        Theme.order_families(module_list)
        menus = []
        menus_titles=[]

        result = ''
        for k in module_list:
            submenu_text = ''
            ## Add the reports in the family:
            report_list = Registry.REPORTS.family[k]
            for r in report_list:
                if r.hidden: continue

                submenu_text+='''<div dojoType="MenuItem2" caption="%s"  onClick="update_container('main','%s');"></div>\n''' % (r.name,FlagFramework.query_type((),family=k,report=r.name))

            if len(submenu_text)>0:
                menus.append('<div dojoType="PopupMenu2" widgetId="%s" toggle="wipe">%s</div>\n' % (k,submenu_text))
                menus_titles.append('<div dojoType="MenuBarItem2" caption="%s" submenuId="%s"></div>\n'%(k,k))


        return result+'''
        %s
        <div dojoType="MenuBar2" id="menubar" layoutAlign="top">%s</div>
        <div dojoType="ToolbarContainer" layoutAlign="top" id="ToolbarContainer" bindArgs="preventCache:false;">
        <div dojoType="Toolbar" id="toolbar"></div></div>
        ''' % ('\n'.join(menus),'\n'.join(menus_titles))

    def naked_render(self,data='',ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % config.VERSION):
        """ Render the ui with minimal interventions """
        result= data
        #print result
        return result

    def render(self, query=FlagFramework.query_type(()), meta='',data='',next=None,previous=None,pageno=None,ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % config.VERSION):
        ## This is a little scriptlet to ensure we are loaded within
        ## dojo environment FIXME: How do we solve the link problem? 
        ## Is it possible? The problem is that the URL is not enough
        ## to specify the state because it might include stored UIs.
        if not query.has_key('__main__'):
            result = '<script>\ntry { djConfig; } catch(err) { document.location=document.location+"&__main__=yes";  };\n</script>'
        else:
            result = ''
        #print data+result
        return data+result

    def raw_render(self,data='',ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % config.VERSION):
        #print data
        return data

    def menu(self,flag,query, result):
        result=flag.ui()

        self.menu_javascript = self.make_menu_javascript(query)
        title="FLAG - Forensic Log Analysis GUI. %s" % config.VERSION

        result.result+=" ".join(
            (self.header % (title),
             '''        <div dojoType="LayoutContainer" widgetId="MainPyFlag" id="MainPyFlag"
             bindArgs="preventCache:false;"
             layoutChildPriority='top-bottom'
             style="width: 100%; height: 100%;">''',             self.menu_javascript,))

        ## If we have something to put in the main pane we put it here:'
        del query['__main__']

        result.result+= '''<div dojoType="ContentPane"
             bindArgs="preventCache:false;"
             cacheContent="false"
             id="main"
             layoutAlign="client"
             style="border: 5px; overflow-y: auto;"
             executeScripts="true">'''

        ## Now create the initial front page:
        result.result+="<img src='images/logo.png'>" + self.footer

        try:
            result.result+='''
            <script>
            dojo.addOnLoad( function() {
            set_url(%r,"f?%s");
            });
            </script>
            ''' % (query['__pane__'],query)
        except KeyError:
            pass

        return result
