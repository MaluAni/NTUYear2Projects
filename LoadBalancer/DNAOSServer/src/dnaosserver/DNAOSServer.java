/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package dnaosserver;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.LinkedList;


/**
 *
 * @author Bogdan
 */
public class DNAOSServer implements Runnable {
    
    
    private int port;
    private LinkedList<String> nodeIPList = new LinkedList<>();
    private LinkedList<Integer> nodePortList = new LinkedList<>();
    private LinkedList<Integer> jobList = new LinkedList<>();
    private LinkedList<String> clientList = new LinkedList<>();
    private InetAddress clientIP;
    private int clientPort;
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        int port = Integer.parseInt(args[0]);
        DNAOSServer coordinator = new DNAOSServer(port); 
        Thread thread = new Thread(coordinator);
        thread.start();
    }
    
    

    public DNAOSServer (int port) {
        this.port = port;
    }

    @Override
    public void run() {
      
        try (DatagramSocket serverSocket = new DatagramSocket(port)) {
            while(true ){
                byte[] recbuffer = new byte[1024];
                DatagramPacket receivedPacket = new DatagramPacket(recbuffer, 0, recbuffer.length);                
                serverSocket.receive(receivedPacket);
                SocketAddress clientDetails = receivedPacket.getSocketAddress();
                int clientPort = Integer.parseInt(clientDetails.toString().split(":")[1]);
                InetAddress clientIP = InetAddress.getByName(clientDetails.toString().split(":")[0].split("/")[1]);
                String receivedMessage = new String(receivedPacket.getData());
                System.out.println("Received: " + receivedMessage + " from " + serverSocket.getRemoteSocketAddress());
                String[] messageArray = receivedMessage.split(",");
                switch (messageArray[0]) {
                    case "REG":
                        nodeIPList.addLast(messageArray[1].split("/")[1].trim());
                        Integer nodePort = Integer.parseInt(messageArray[2].trim());
                        nodePortList.addLast(nodePort);
                        System.out.println("Node added to list: " + nodeIPList + nodePortList);
                        if ( jobList.isEmpty()) {
                            System.out.println("No jobs available - waiting for jobs...");
                            break;
                        }else {
                            while(jobList.isEmpty() == false){
                            System.out.println("Sending job...");
                            String firstJob = jobList.getFirst().toString();
                            InetAddress firstIP = InetAddress.getByName(nodeIPList.getFirst()); 
                            byte[] byteMessageSent = ("JOB, " + firstJob).getBytes();
                            DatagramPacket PACKETSent = new DatagramPacket(byteMessageSent, 
                                    byteMessageSent.length, firstIP, nodePortList.getFirst());
                            serverSocket.send(PACKETSent);
                            nodeIPList.addLast(nodeIPList.remove(0));
                            nodePortList.addLast(nodePortList.remove(0));
                            jobList.remove(0);
                            }
                        }
                       
                    break;
                    case "JOB":
                        jobList.addLast(Integer.parseInt(messageArray[1].trim()));
                        System.out.println("JOB added to list: " + jobList);
                        while (jobList.isEmpty() == false) {
                            if (nodeIPList.isEmpty() == false){
                            System.out.println("Sending job...");
                            String firstJob = jobList.getFirst().toString();
                            InetAddress firstIP = InetAddress.getByName(nodeIPList.getFirst()); 
                            byte[] byteMessageSent = ("JOB, " + firstJob).getBytes();
                            DatagramPacket PACKETSent = new DatagramPacket(byteMessageSent, byteMessageSent.length, 
                                    firstIP, nodePortList.getFirst());
                            serverSocket.send(PACKETSent);
                            nodeIPList.addLast(nodeIPList.remove(0));
                            nodePortList.addLast(nodePortList.remove(0));
                            jobList.remove(0);
                            }else{
                                System.out.println("No nodes available, waiting for nodes...");
                                break;
                            }
                        }
                    break;
                    case "CLIENT":
                        clientList.add(messageArray[1].split("/")[1].trim());
                        clientList.add(messageArray[2].trim());
                        clientIP = InetAddress.getByName(clientList.getFirst());
                        clientPort = Integer.parseInt(clientList.getLast());
                        System.out.println("Client connected " + clientList);
                    break;
                    case "JOBEND":
                        String jobDataIP = messageArray[1].split("seconds finished on")[1]
                                .split("from")[0].split("/")[1].trim();
                        int jobDataTime = Integer.parseInt(messageArray[1].split("JOB for")[1]
                                .split("seconds")[0].trim());
                        clientIP = InetAddress.getByName(clientList.getFirst());
                        clientPort = Integer.parseInt(clientList.getLast());
                        byte[] jobEndMsg = ("JOBEND received from " + jobDataIP + " on a " 
                                + jobDataTime + " second job.").getBytes();
                        DatagramPacket jobEndPACKET = new DatagramPacket(jobEndMsg, 
                                jobEndMsg.length, clientIP, clientPort);
                        serverSocket.send(jobEndPACKET);
                    break;
                }
                try{
                    Thread wait = new Thread();
                    String sendMsg = "Server received message";
                    DatagramPacket sendPacket = new DatagramPacket(
                    sendMsg.getBytes(),
                    sendMsg.length(),
                    clientIP,
                    clientPort
                );
                    wait.sleep(1500);
                    serverSocket.send(sendPacket);
                }catch ( InterruptedException e) {
                    e.printStackTrace();
                }
                
            }
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
