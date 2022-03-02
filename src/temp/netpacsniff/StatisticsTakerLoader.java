/*Author Aditya
 * 
 * 
 */

package netpacsniff;
import java.util.*;

import netpacksniff.stat.ApplicationProtocolStat;
import netpacksniff.stat.FreeMemStat;
import netpacksniff.stat.StatisticsTaker;
import netpacksniff.stat.NetworkProtocolStat;
import netpacksniff.stat.PacketStat;
import netpacksniff.stat.TransportProtocolStat;


public class StatisticsTakerLoader
{
	static Vector stakers=new Vector();
	
	static void loadStatisticsTaker(){
		stakers.addElement(new PacketStat());
		stakers.addElement(new NetworkProtocolStat());
		stakers.addElement(new TransportProtocolStat());
		stakers.addElement(new ApplicationProtocolStat());
		stakers.addElement(new FreeMemStat());
	}
	
	public static StatisticsTaker[] getStatisticsTakers(){
		StatisticsTaker[] array=new StatisticsTaker[stakers.size()];
		
		for(int i=0;i<array.length;i++)
			array[i]=(StatisticsTaker)stakers.elementAt(i);
			
		return array;
	}
	
	public static StatisticsTaker getStatisticsTakerAt(int index){
		return (StatisticsTaker)stakers.get(index);
	}
}
