/*Author Aditya
 * 
 */


package netpacsniff;
import java.util.*;

import netpacksniff.analyzer.*;


public class PacketAnalyzerLoader
{
	static Vector analyzers=new Vector();
	
	static void loadDefaultAnalyzer(){
		analyzers.addElement(new PacketAnalyzer());
		analyzers.addElement(new EthernetAnalyzer());
		analyzers.addElement(new IPv4Analyzer());
		analyzers.addElement(new IPv6Analyzer());
		analyzers.addElement(new TCPAnalyzer());
		analyzers.addElement(new UDPAnalyzer());
		analyzers.addElement(new ICMPAnalyzer());
		analyzers.addElement(new HTTPAnalyzer());
		analyzers.addElement(new FTPAnalyzer());
		analyzers.addElement(new TelnetAnalyzer());
		analyzers.addElement(new SSHAnalyzer());
		analyzers.addElement(new SMTPAnalyzer());
		analyzers.addElement(new POP3Analyzer());
		analyzers.addElement(new ARPAnalyzer());
	}
	
	public static PacketAnalyzerAbstract[] getAnalyzers(){
		PacketAnalyzerAbstract[] array=new PacketAnalyzerAbstract[analyzers.size()];
		
		for(int i=0;i<array.length;i++)
			array[i]=(PacketAnalyzerAbstract)analyzers.elementAt(i);
			
		return array;
	}
	
	public static PacketAnalyzerAbstract[] getAnalyzersOf(int layer){
		Vector v=new Vector();
		
		for(int i=0;i<analyzers.size();i++)
			if(((PacketAnalyzerAbstract)analyzers.elementAt(i)).layer==layer)
				v.addElement(analyzers.elementAt(i));
		
		PacketAnalyzerAbstract[] res=new PacketAnalyzerAbstract[v.size()];
		for(int i=0;i<res.length;i++)
			res[i]=(PacketAnalyzerAbstract)v.elementAt(i);
		
		return res;
	}
}
