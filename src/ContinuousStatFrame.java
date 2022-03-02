/*Author Aditya
 * 
 * 
 * This class shows the statistics in the form of graphs and similar to the cumulative statistics frame
 */


package netpacksniff.ui;
import java.awt.BorderLayout;
import java.util.Enumeration;
import java.util.Vector;

import jpcap.packet.Packet;
import netpacksniff.stat.StatisticsTaker;
import netpacksniff.ui.graph.LineGraph;


public class ContinuousStatFrame extends StatFrame
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LineGraph lineGraph;
	
	StatisticsTaker staker;
	int statType;
	boolean drawTimescale; //true-> time, false->packet#
	int count,currentCount=0;
	long currentSec=0;
	
	public static ContinuousStatFrame openWindow(Vector packets,StatisticsTaker staker){
		ContinuousStatFrame frame=new ContinuousStatFrame(packets,5,true,staker,0);
		frame.setVisible(true);
		return frame;
	}
	
	ContinuousStatFrame(Vector packets,int count,boolean isTime,StatisticsTaker staker,int type){
		super(staker.getName()+" ["+staker.getStatTypes()[type]+"]");
		this.staker=staker;
		this.drawTimescale=isTime;this.count=count;
		statType=type;
		
		lineGraph=new LineGraph(staker.getLabels());
		
		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(lineGraph,BorderLayout.CENTER);
		setSize(300,300);
		
		if(packets==null || packets.size()==0) return;
		
		Enumeration en=packets.elements();
		currentSec=((Packet)packets.firstElement()).sec;
		currentCount=0;
		int index=0;
		if(isTime){
			while(index<packets.size()){
				Packet p=(Packet)packets.elementAt(index++);
				
				while(index<packets.size() && p.sec-currentSec<=count){
					staker.addPacket(p);
					p=(Packet)packets.elementAt(index++);
				}
				if(index==packets.size()) break;
				currentSec+=count;
				index--;
				lineGraph.addValue(staker.getValues(type));
				staker.clear();
			}
		}else{
			while(en.hasMoreElements()){
				for(int i=0;en.hasMoreElements() && i<count;i++,currentCount++)
					staker.addPacket((Packet)en.nextElement());
				if(!en.hasMoreElements()) break;
				currentCount=0;
				lineGraph.addValue(staker.getValues(type));
				staker.clear();
			}
		}
	}
	
	public void addPacket(Packet p){
		staker.addPacket(p);
		if(drawTimescale){
			if(currentSec==0) currentSec=p.sec;
			if(p.sec-currentSec>count){
				lineGraph.addValue(staker.getValues(statType));
				staker.clear();
				currentSec+=count;
				if(p.sec-currentSec>count)
					for(long s=p.sec-currentSec-count;s>count;s-=count){
						lineGraph.addValue(staker.getValues(statType));
					}
			}
		}else{
			currentCount++;
			if(currentCount==count){
				lineGraph.addValue(staker.getValues(statType));
				staker.clear();
				currentCount=0;
			}
		}
	}
	
	public void clear(){
		currentCount=0;
		currentSec=0;
		lineGraph.clear();
	}

	void fireUpdate(){
		repaint();
	}
}
