/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package dnaosnode;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.LinkedList;


/**
 *
 * @author Bogdan
 */
public class DNAOSNode implements Runnable{

    private final int port;
    private InetAddress coordinatorIP;
    private int coordinatorPort;
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 3){
            System.out.println("Not enough arguments provided, need 3: coordIP, local port, coord port");
            System.out.println("Usage: 192.168.1.1 55000 4000");
            System.exit(0);
        }else{
        int port = Integer.parseInt(args[1]);
        int coordinatorPort = Integer.parseInt(args[2]);
        InetAddress coordinatorIP = InetAddress.getByName(args[0]);               
        DNAOSNode node = new DNAOSNode(coordinatorIP, port, coordinatorPort);
        Thread thread = new Thread(node);
        thread.start();
        }
    }
    
    public DNAOSNode (InetAddress coordIP, int port, int coordPort) {
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
            String message = "REG, " + localIP + ", " + port; 
            byte[] sendbuffer = message.getBytes();
            DatagramPacket sentPacket = new DatagramPacket(sendbuffer, 0, 
                    sendbuffer.length, coordinatorIP, coordinatorPort);
            clientSocket.send(sentPacket);
            while (true) {                
                byte[] recbuffer = new byte[1024];
                DatagramPacket receivedPacket = new DatagramPacket(recbuffer, 0, recbuffer.length);                
                clientSocket.receive(receivedPacket);
                String receivedMessage = new String(receivedPacket.getData());
                System.out.println(receivedMessage);
                String[] msgHead = receivedMessage.split(",");
                
                if (msgHead[0].equals("JOB")){
                    LinkedList<Integer> jobQueue = new LinkedList<>();
                    jobQueue.add(Integer.parseInt(msgHead[1].trim()));
                    while (jobQueue.isEmpty() == false){
                    System.out.println("Running JOB, "+jobQueue.getFirst()+" seconds...");
                    try{
                        Thread wait = new Thread();
                        int timer = jobQueue.getFirst();
                        wait.sleep(timer*1000);
                        jobQueue.remove(0);
                        System.out.println("JOB finished, waiting for jobs...");
                        byte[] endJobMsg = ("JOBEND, JOB for " + timer + " seconds finished on " 
                                + localIP).getBytes();
                        DatagramPacket jobEndPacket = new DatagramPacket(endJobMsg, 
                                endJobMsg.length, coordinatorIP, coordinatorPort);
                        clientSocket.send(jobEndPacket);
                    } catch ( InterruptedException e) {
                    e.printStackTrace();
                }
                        
                    }
                }
            }
                
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("Timeout error");
        }
    }
}
