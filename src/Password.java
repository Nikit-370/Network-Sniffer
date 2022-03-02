package netpacksniff.ui;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class Password extends JFrame{

	/**
	 * @param args
	 */
	public Password()
	{
		JTextField id=new JTextField();
		JPasswordField pass=new JPasswordField();
		JPanel pa=new JPanel();
		JLabel l1=new JLabel("UserID");
		JLabel l2=new JLabel("Password");
		pa.add(l1);
		pa.add(id);
		pa.add(l2);
		pa.add(pass);
		
		
	}
	public static void main(String[] args) {
		// TODO Auto-generated method stub
      Password p=new Password();
	}

}
