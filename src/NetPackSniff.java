/* 
 * Author Aditya
 * 
 * This is the main class that loads the packetsniffer and also loads all the user 
 * interfaces like windows,graphs etc.This class contains the main method of the project.
 *  
*/
package netpacsniff;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import java.util.Vector;

import javax.swing.JOptionPane;

import netpacksniff.ui.Frame;



public class NetPackSniff
{
	public static Properties JDProperty;
	
	public static javax.swing.JFileChooser chooser=new javax.swing.JFileChooser();

	static Vector frames=new Vector();

	public static void main(String[] args){
		try{
			Class c=Class.forName("jpcap.JpcapCaptor");
		}catch(ClassNotFoundException e){
			JOptionPane.showMessageDialog(null,"Cannot find Jpcap. Please download and install Jpcap before running.");
			System.exit(0);
		}
				
		PacketAnalyzerLoader.loadDefaultAnalyzer();
		StatisticsTakerLoader.loadStatisticsTaker();
		loadProperty();
		
		openNewWindow();
		
	}
	
	public static void saveProperty(){
		if(JDProperty==null) return;
		try{
			JDProperty.store((OutputStream)new FileOutputStream("JpcapDumper.property"),"JpcapDumper");
			//JDProperty.store(new FileOutputStream("JpcapDumper.property"),"JpcapDumper");
		}catch(IOException e){
		}catch(ClassCastException e){
		}
	}
	
	static void loadProperty(){
		try{
			JDProperty=new Properties();
			JDProperty.load((InputStream)new FileInputStream("JpcapDumper.property"));
		}catch(IOException e){
		}
	}
	
	public static void openNewWindow(){
		Captor captor=new Captor();
		frames.add(Frame.openNewWindow(captor));
	}
	
	public static void closeWindow(Frame frame){
		frame.captor.stopCapture();
		frame.captor.saveIfNot();
		frame.captor.closeAllWindows();
		frames.remove(frame);
		frame.dispose();
		if(frames.isEmpty()){
			saveProperty();
			System.exit(0);
		}
	}
	
	protected void finalize() throws Throwable{
		saveProperty();
	}
}
