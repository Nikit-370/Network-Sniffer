/*This is an abstract class.All the other classes in this pckage extends this class
 * 
 */
package netpacksniff.stat;
import java.util.Vector;
import jpcap.packet.Packet;

public abstract class StatisticsTaker
{
	public abstract String getName();//Gets the name of the 

	public abstract void analyze(Vector packets);
	public abstract void addPacket(Packet p);
	
	public abstract String[] getLabels();
	public abstract String[] getStatTypes();
	public abstract long[] getValues(int index);
	
	public abstract void clear();
	
	public StatisticsTaker newInstance(){
		try{
			return (StatisticsTaker)this.getClass().newInstance();
		}catch(Exception e){
			return null;
		}
	}
}