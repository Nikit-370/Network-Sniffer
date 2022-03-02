/*This class shows the pane i.e when clicked on a check box in the protocol menu they will be displayed 
 *  
 * 
 */
package netpacksniff.ui;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;

import netpacksniff.analyzer.PacketAnalyzerAbstract;
import netpacsniff.Captor;
import netpacsniff.PacketAnalyzerLoader;
import netpacsniff.NetPackSniff;

import java.util.*;

import jpcap.packet.*;

class TablePane extends JPanel implements ActionListener,ListSelectionListener
{
	Table table;
	TableTree tree;
	TableTextArea text;
	Captor captor;
	PacketAnalyzerAbstract[] analyzers;
	
	JMenu[] tableViewMenu=new JMenu[4];
	TablePane(Captor captor){
		this.captor=captor;
		table=new Table(this,captor);
		tree=new TableTree();
		text=new TableTextArea();
		
		JSplitPane splitPane=new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		JSplitPane splitPane2=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		splitPane.setTopComponent(table);
		splitPane2.setTopComponent(tree);
		splitPane2.setBottomComponent(new JScrollPane(text));
		splitPane.setBottomComponent(splitPane2);
		splitPane.setDividerLocation(200);
		splitPane2.setDividerLocation(200);
		
		tableViewMenu[0]=new JMenu("Datalink Layer");
		tableViewMenu[1]=new JMenu("Network Layer");
		tableViewMenu[2]=new JMenu("Transport Layer");
		tableViewMenu[3]=new JMenu("Application Layer");
		analyzers=PacketAnalyzerLoader.getAnalyzers();
		JMenuItem item,subitem;
		for(int i=0;i<analyzers.length;i++){
			item=new JMenu(analyzers[i].getProtocolName());
			String[] valueNames=analyzers[i].getValueNames();
			if(valueNames==null) continue;
			for(int j=0;j<valueNames.length;j++){
				subitem=new JCheckBoxMenuItem(valueNames[j]);
				subitem.setActionCommand("TableView"+i);
				subitem.addActionListener(this);
				item.add(subitem);
			}
			tableViewMenu[analyzers[i].layer].add(item);
		}

		setLayout(new BorderLayout());
		add(splitPane,BorderLayout.CENTER);

		loadProperty();
		setSize(400,200);
	}
	
	void fireTableChanged(){
		table.fireTableChanged();
	}
	
	void clear(){
		table.clear();
	}
	
	public void setTableViewMenu(JMenu menu){
		menu.add(tableViewMenu[0]);
		menu.add(tableViewMenu[1]);
		menu.add(tableViewMenu[2]);
		menu.add(tableViewMenu[3]);
	}
	
	public void actionPerformed(ActionEvent evt){
		String cmd=evt.getActionCommand();
		
		if(cmd.startsWith("TableView")){
			int index=Integer.parseInt(cmd.substring(9));
			JCheckBoxMenuItem item=(JCheckBoxMenuItem)evt.getSource();
			table.setTableView(analyzers[index],item.getText(),item.isSelected());
		}
	}
	
	public void valueChanged(ListSelectionEvent evt){
		if(evt.getValueIsAdjusting()) return;
		
		int index=((ListSelectionModel)evt.getSource()).getMinSelectionIndex();
		if(index>=0){
			Packet p=(Packet)captor.getPackets().get(table.sorter.getOriginalIndex(index));
			tree.analyzePacket(p);
			text.showPacket(p);
		}
	}
	
	void loadProperty(){
		if(NetPackSniff.JDProperty.getProperty("TableView")!=null){
			//get all menus
			Component[] menus=new Component[analyzers.length];
			int k=0;
			for(int j=0;j<tableViewMenu[0].getMenuComponents().length;j++)
				menus[k++]=tableViewMenu[0].getMenuComponents()[j];
			for(int j=0;j<tableViewMenu[1].getMenuComponents().length;j++)
				menus[k++]=tableViewMenu[1].getMenuComponents()[j];
			for(int j=0;j<tableViewMenu[2].getMenuComponents().length;j++)
				menus[k++]=tableViewMenu[2].getMenuComponents()[j];
			for(int j=0;j<tableViewMenu[3].getMenuComponents().length;j++)
				menus[k++]=tableViewMenu[3].getMenuComponents()[j];
			
			//load ptoperty
			StringTokenizer status=new StringTokenizer(NetPackSniff.JDProperty.getProperty("TableView"),",");
			
			while(status.hasMoreTokens()){
				StringTokenizer s=new StringTokenizer(status.nextToken(),":");
				if(s.countTokens()==2){
					String name=s.nextToken(),valueName=s.nextToken();
					//for(int i=0;i<analyzers.length;i++)
						//if(analyzers[i].getProtocolName().equals(name)){
					for(int i=0;i<menus.length;i++){
						if(((JMenu)menus[i]).getText()==null || name==null) continue;
						if(((JMenu)menus[i]).getText().equals(name)){
							Component[] vn=((JMenu)menus[i]).getMenuComponents();
							//table.setTableView(analyzers[i],n,true);
							for(int j=0;j<vn.length;j++)
								if(valueName.equals(((JCheckBoxMenuItem)vn[j]).getText())){
									((JCheckBoxMenuItem)vn[j]).setState(true);
									break;
								}
							break;
						}
					}
					
					for(int i=0;i<analyzers.length;i++)
						if(analyzers[i].getProtocolName().equals(name)){
							table.setTableView(analyzers[i],valueName,true);
							break;
						}
				}
			}
		}
	}
	
	void saveProperty(){
		String[] viewStatus=table.getTableViewStatus();
		if(viewStatus.length>0){
			StringBuffer buf=new StringBuffer(viewStatus[0]);
			for(int i=1;i<viewStatus.length;i++)
				buf.append(","+viewStatus[i]);
				NetPackSniff.JDProperty.put("TableView",buf.toString());
		}
	}
}
