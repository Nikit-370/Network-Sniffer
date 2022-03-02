/*Author Aditya
 * 
 */
package netpacsniff;

import java.io.File;
import java.util.Vector;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import netpacksniff.stat.StatisticsTaker;
import netpacksniff.ui.CaptureDialog;
import netpacksniff.ui.ContinuousStatFrame;
import netpacksniff.ui.CumlativeStatFrame;
import netpacksniff.ui.Frame;
import netpacksniff.ui.StatFrame;


public class Captor {
	long MAX_PACKETS_HOLD=10000;

	Vector packets = new Vector();

	JpcapCaptor jpcap=null;

	boolean isLiveCapture;
	boolean isSaved = false;

	Frame frame;

	public void setJDFrame(Frame frame){
		this.frame=frame;
	}

	public Vector getPackets(){
		return packets;
	}


	public void capturePacketsFromDevice() {
		if(jpcap!=null)
			jpcap.close();
		jpcap = CaptureDialog.getJpcap(frame);
		clear();
		
		if (jpcap != null) {
			isLiveCapture = true;
			frame.disableCapture();

			startCaptureThread();
		}
	}

	public void loadPacketsFromFile() {
		isLiveCapture = false;
		clear();

		int ret = NetPackSniff.chooser.showOpenDialog(frame);
		if (ret == JFileChooser.APPROVE_OPTION) {
			String path = NetPackSniff.chooser.getSelectedFile().getPath();
			String filename = NetPackSniff.chooser.getSelectedFile().getName();

			try {
				if(jpcap!=null){
					jpcap.close();
				}
				jpcap = JpcapCaptor.openFile(path);
			} catch (java.io.IOException e) {
				JOptionPane.showMessageDialog(
					frame,
					"Can't open file: " + path);
				e.printStackTrace();
				return;
			}

			frame.disableCapture();

			startCaptureThread();
		}
	}

	private void clear(){
		packets.clear();
		frame.clear();

		for(int i=0;i<sframes.size();i++)
			((StatFrame)sframes.get(i)).clear();
	}

	public void saveToFile() {
		if (packets == null)
			return;

		int ret = NetPackSniff.chooser.showSaveDialog(frame);
		if (ret == JFileChooser.APPROVE_OPTION) {
			File file = NetPackSniff.chooser.getSelectedFile();

			if (file.exists()) {
				if (JOptionPane
					.showConfirmDialog(
						frame,
						"Overwrite " + file.getName() + "?",
						"Overwrite?",
						JOptionPane.YES_NO_OPTION)
					== JOptionPane.NO_OPTION) {
					return;
				}
			}

			try {
				//System.out.println("link:"+info.linktype);
				//System.out.println(lastJpcap);
				JpcapWriter writer = JpcapWriter.openDumpFile(jpcap,file.getPath());

				for (int i = 0; i < packets.size(); i++) {
					writer.writePacket((Packet) packets.elementAt(i));
				}

				writer.close();
				isSaved = true;
				//JOptionPane.showMessageDialog(frame,file+" was saved correctly.");
			} catch (java.io.IOException e) {
				e.printStackTrace();
				JOptionPane.showMessageDialog(
					frame,
					"Can't save file: " + file.getPath());
			}
		}
	}

	public void stopCapture() {
		stopCaptureThread();
	}

	public void saveIfNot() {
		if (isLiveCapture && !isSaved) {
			int ret =
				JOptionPane.showConfirmDialog(
					null,
					"Save this data?",
					"Save this data?",
					JOptionPane.YES_NO_OPTION);
			if (ret == JOptionPane.YES_OPTION)
				saveToFile();
		}
	}

	Vector sframes=new Vector();
	public void addCumulativeStatFrame(StatisticsTaker taker) {
		sframes.add(CumlativeStatFrame.openWindow(packets,taker.newInstance()));
	}

	public void addContinuousStatFrame(StatisticsTaker taker) {
		sframes.add(ContinuousStatFrame.openWindow(packets,taker.newInstance()));
	}

	public void closeAllWindows(){
		for(int i=0;i<sframes.size();i++)
			((StatFrame)sframes.get(i)).dispose();
	}



	private Thread captureThread;

	private void startCaptureThread() {
		if (captureThread != null)
			return;

		captureThread = new Thread(new Runnable(){
			//body of capture thread
			public void run() {
				while (captureThread != null) {
					if (jpcap.processPacket(1, handler) == 0 && !isLiveCapture)
						stopCaptureThread();
					Thread.yield();
				}

				jpcap.breakLoop();
				//jpcap = null;
				frame.enableCapture();
			}
		});
		captureThread.setPriority(Thread.MIN_PRIORITY);
		
		frame.startUpdating();
		for(int i=0;i<sframes.size();i++){
			((StatFrame)sframes.get(i)).startUpdating();
		}
		
		captureThread.start();
	}

	void stopCaptureThread() {
		captureThread = null;
		frame.stopUpdating();
		for(int i=0;i<sframes.size();i++){
			((StatFrame)sframes.get(i)).stopUpdating();
		}
	}


	private PacketReceiver handler=new PacketReceiver(){
		public void receivePacket(Packet packet) {
			packets.addElement(packet);
			while (packets.size() > MAX_PACKETS_HOLD) {
				packets.removeElementAt(0);
			}
			if (!sframes.isEmpty()) {
				for (int i = 0; i < sframes.size(); i++)
					((StatFrame)sframes.get(i)).addPacket(packet);
			}
			isSaved = false;
		}
	};

}
