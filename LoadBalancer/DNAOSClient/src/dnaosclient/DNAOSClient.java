/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package dnaosclient;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.LinkedList;
import java.util.Scanner;


/**
 *
 * @author Bogdan
 */
public class DNAOSClient implements Runnable{

    private final int port;
    private InetAddress coordinatorIP;
    private int coordinatorPort;
    private LinkedList<String> jobsCompleted = new LinkedList<>();
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        // TODO code application logic here
        int port = Integer.parseInt(args[1]);
        int coordinatorPort = Integer.parseInt(args[2]);
        InetAddress coordinatorIP = InetAddress.getByName(args[0]);
        DNAOSClient client = new DNAOSClient(coordinatorIP, port, coordinatorPort);
        Thread thread = new Thread(client);
        thread.start();
    }
    
    public DNAOSClient (InetAddress coordIP, int port, int coordPort) {
        this.port = port;
        this.coordinatorIP = coordIP;
        this.coordinatorPort = coordPort;
    }

    @Override
    public void run() {
        
        try (DatagramSocket clientSocket = new DatagramSocket(port)) {
            
            clientSocket.setSoTimeout(0);
            InetAddress localIP = InetAddress.getLocalHost();
            if (localIP == null){
                localIP = InetAddress.getByName("localhost"); 
            }
            String connMessage = "CLIENT, " + localIP + ", " + port;
            byte[] connect = connMessage.getBytes();
            DatagramPacket connPacket = new DatagramPacket(connect, 0, connect.length, 
                    coordinatorIP, coordinatorPort);
            clientSocket.send(connPacket);
            while (true){
                try{
                Thread send = new Thread();
                
                System.out.println(">");
                Scanner keyboardInput = new Scanner(System.in);
                String message = keyboardInput.nextLine().toUpperCase();
                byte[] sendbuffer = message.getBytes();
                DatagramPacket sentPacket = new DatagramPacket(sendbuffer, 0, 
                        sendbuffer.length, coordinatorIP, coordinatorPort);
                send.sleep(100);
                clientSocket.send(sentPacket);
                }catch ( InterruptedException e) {
                    e.printStackTrace();
                }
                byte[] recbuffer = new byte[1024];
                DatagramPacket receivedPacket = new DatagramPacket(recbuffer, 0, recbuffer.length);                
                clientSocket.receive(receivedPacket);
                String receivedMessage = new String(receivedPacket.getData());                
                String[] msgArray = receivedMessage.split(" ");
                switch (msgArray[0]){
                    case "JOBEND":
                        jobsCompleted.add(receivedMessage);
                        System.out.println("Received JOBEND message, added to completed jobs list. " 
                                + jobsCompleted);
                        break;
                    default:
                        System.out.println(receivedMessage);
                       break;
                }
                              
            }
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("Timeout error");
        }
    }
}
