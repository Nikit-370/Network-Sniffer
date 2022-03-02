package netpacksniff.stat;
import jpcap.packet.*;
import java.util.*;

import netpacksniff.analyzer.PacketAnalyzerAbstract;
import netpacsniff.PacketAnalyzerLoader;


public class NetworkProtocolStat extends StatisticsTaker
{
	PacketAnalyzerAbstract[] analyzers;
	long[] numOfPs;
	long totalPs;
	long[] sizeOfPs;
	long totalSize;
	String[] labels;
	static final String[] types={"# of packets","% of packets","total packet size","% of size"};
	
	public NetworkProtocolStat(){
		analyzers=PacketAnalyzerLoader.getAnalyzersOf(PacketAnalyzerAbstract.NETWORK_LAYER);
		numOfPs=new long[analyzers.length+1];
		sizeOfPs=new long[analyzers.length+1];

		labels=new String[analyzers.length+1];
		for(int i=0;i<analyzers.length;i++)
			labels[i]=analyzers[i].getProtocolName();
		labels[analyzers.length]="Other";
	}
	
	public String getName(){
		return "Netowrk Layer Protocol Ratio";
	}
	
	public void analyze(Vector packets){
		for(int i=0;i<packets.size();i++){
			Packet p=(Packet)packets.elementAt(i);
			totalPs++;
			totalSize+=p.len;
			
			boolean flag=false;
			for(int j=0;j<analyzers.length;j++)
				if(analyzers[j].isAnalyzable(p)){
					numOfPs[j]++;
					totalPs++;
					sizeOfPs[j]+=p.len;
					flag=true;
					break;
				}
			if(!flag){
				numOfPs[numOfPs.length-1]++;
				sizeOfPs[sizeOfPs.length-1]+=p.len;
			}
		}
	}
	
	public void addPacket(Packet p){
		boolean flag=false;
		totalPs++;
		totalSize+=p.len;
		for(int j=0;j<analyzers.length;j++)
			if(analyzers[j].isAnalyzable(p)){
				numOfPs[j]++;
				sizeOfPs[j]+=p.len;
				flag=true;
				break;
			}
		if(!flag){
			numOfPs[numOfPs.length-1]++;
			sizeOfPs[sizeOfPs.length-1]+=p.len;
		}
	}
	
	public String[] getLabels(){
		return labels;
	}
	
	public String[] getStatTypes(){
		return types;
	}
	
	public long[] getValues(int index){
		switch(index){
			case 0: //# of packets
				if(numOfPs==null) return new long[0];
				return numOfPs;
			case 1: //% of packets
				long[] percents=new long[numOfPs.length];
				if(totalPs==0) return percents;
				for(int i=0;i<numOfPs.length;i++)
					percents[i]=numOfPs[i]*100/totalPs;
				return percents;
			case 2: //total packet size
				if(sizeOfPs==null) return new long[0];
				return sizeOfPs;
			case 3: //% of size
				long[] percents2=new long[sizeOfPs.length];
				if(totalSize==0) return percents2;
				for(int i=0;i<sizeOfPs.length;i++)
					percents2[i]=sizeOfPs[i]*100/totalSize;
				return percents2;
			default:
				return null;
		}
	}
	
	
	public void clear(){
		numOfPs=new long[analyzers.length+1];
		sizeOfPs=new long[analyzers.length+1];
		totalPs=0;
		totalSize=0;
	}
}
