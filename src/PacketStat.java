/*
 *   This class calculates the statistics of the packet like the Total packet,Total packet size,Average packet size
 *   bits/sec,pkts/sec etc 
 */

package netpacksniff.stat;
import jpcap.packet.*;
import java.util.*;

public class PacketStat extends StatisticsTaker
{
	static final String[] types={
		"Total packet #",
		"Total packet size",
		"Average packet size",
		"bits/s",
		"pkts/s"
	};
	static final String[] label={"Value"};
	
	long numOfPs,sizeOfPs;
	Date first,last;
	
	public String getName(){
		return "Overall information";
	}
	
	public void analyze(Vector packets){
		if(packets.size()>0){
			Packet fp=(Packet)packets.firstElement(),lp=(Packet)packets.lastElement();
			first=new Date(fp.sec*1000+fp.usec/1000);
			last=new Date(lp.sec*1000+lp.usec/1000);
		}
		
		for(int i=0;i<packets.size();i++){
			numOfPs++;
			sizeOfPs+=((Packet)packets.elementAt(i)).len;
		}
	}
	
	public void addPacket(Packet p){
		if(first==null){
			first=new Date(p.sec*1000+p.usec/1000);
		}
		last=new Date(p.sec*1000+p.usec/1000);
		
		numOfPs++;
		sizeOfPs+=p.len;
	}
	
	public String[] getLabels(){return label;}
	public String[] getStatTypes(){return types;}
	
	public long[] getValues(int index){
		long[] ret=new long[1];
		switch(index){
			case 0: //Total packet #
				 ret[0]=numOfPs;
				 return ret;
			case 1: //Total packet size
				ret[0]=sizeOfPs;
				return ret;
			case 2: //Avecage packet size
				if(numOfPs==0) ret[0]=0;
				else ret[0]=sizeOfPs/numOfPs;
				return ret;
			case 3: //bits/s
			case 4: //pkts/s
				if(first==null) ret[0]=0;
				else{
					long sec=(last.getTime()-first.getTime())*1000;
					if(sec==0) ret[0]=0;
					else
						if(index==3) ret[0]=sizeOfPs*8/sec;
						else ret[0]=numOfPs/sec;
				}
				return ret;
			default:
				return null;
		}
	}
	
	public void clear(){
		numOfPs=0;sizeOfPs=0;
		first=null;last=null;
	}
}
