/*Author Aditya
 * 
 */


package netpacksniff.analyzer;
import jpcap.packet.*;

public class ARPAnalyzer extends PacketAnalyzerAbstract
{
	private static final String[] valueNames={
		"Hardware Type",
		"Protocol Type",
		"Hardware Address Length",
		"Protocol Address Length",
		"Operation",
		"Sender Hardware Address",
		"Sender Protocol Address",
		"Target Hardware Address",
		"Target Protocol Address"
	};
	private ARPPacket arp;
	
	public ARPAnalyzer(){
		layer=NETWORK_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		return (p instanceof ARPPacket);
	}
	
	public String getProtocolName(){
		return "ARP/RARP";
	}
	
	public String[] getValueNames(){
		return valueNames;
	}
	
	public void analyze(Packet p){
		if(!isAnalyzable(p)) return;
		arp=(ARPPacket)p;
	}
	
	public Object getValue(String valueName){
		for(int i=0;i<valueNames.length;i++)
			if(valueNames[i].equals(valueName))
				return getValueAt(i);
		
		return null;
	}
	
	Object getValueAt(int index){
		switch(index){
			case 0: 
			switch(arp.hardtype){
				case ARPPacket.HARDTYPE_ETHER: return "Ethernet ("+arp.hardtype+")";
				case ARPPacket.HARDTYPE_IEEE802: return "Token ring ("+arp.hardtype+")";
				case ARPPacket.HARDTYPE_FRAMERELAY: return "Frame relay ("+arp.hardtype+")";
				default: return new Integer(arp.hardtype);
			}
			case 1:
			switch(arp.prototype){
				case ARPPacket.PROTOTYPE_IP: return "IP ("+arp.prototype+")";
				default: return new Integer(arp.prototype);
			}
			case 2: return new Integer(arp.hlen);
			case 3: return new Integer(arp.plen);
			case 4:
			switch(arp.operation){
				case ARPPacket.ARP_REQUEST: return "ARP Request";
				case ARPPacket.ARP_REPLY: return "ARP Reply";
				case ARPPacket.RARP_REQUEST: return "Reverse ARP Request";
				case ARPPacket.RARP_REPLY: return "Reverse ARP Reply";
				case ARPPacket.INV_REQUEST: return "Identify peer Request";
				case ARPPacket.INV_REPLY: return "Identify peer Reply";
				default: return new Integer(arp.operation);
			}
			case 5: return arp.getSenderHardwareAddress();
			case 6: return arp.getSenderProtocolAddress();
			case 7: return arp.getTargetHardwareAddress();
			case 8: return arp.getTargetProtocolAddress();
			default: return null;
		}
	}
	
	public Object[] getValues(){
		Object[] v=new Object[valueNames.length];
		for(int i=0;i<valueNames.length;i++)
			v[i]=getValueAt(i);
		
		return v;
	}
}
