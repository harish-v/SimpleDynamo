package edu.buffalo.cse.cse486586.simpledynamo;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDynamoProvider extends ContentProvider {

    static final String TAG = SimpleDynamoProvider.class.getSimpleName();
    static final int SERVER_PORT = 10000;
    static Node nodeList = null;
    static MatrixCursor cursor = null;
    static boolean isQueryAllComplete = false;
    static boolean isDeleteAllComplete = false;
    static boolean replicate = false;
    static Map<String, String> avdPort = new HashMap<>();
    static Map<String, Set<String>> replicaSet = new HashMap<>();
    static Map<String, String> hashPort = new HashMap<>();
    static List<String> nodeCollection = new ArrayList<>();
    String tempKey = "";
    int wait = 0;
    int delcheck = 0;
    Set<String> keylist = new HashSet<String>();

    static {
        Set<String> temp = new HashSet<>();
        temp.add("11116");
        temp.add("11120");
        replicaSet.put("11108", temp);

        temp = null;
        temp = new HashSet<>();
        temp.add("11120");
        temp.add("11124");
        replicaSet.put("11116", temp);

        temp = null;
        temp = new HashSet<>();
        temp.add("11124");
        temp.add("11112");
        replicaSet.put("11120", temp);

        temp = null;
        temp = new HashSet<>();
        temp.add("11112");
        temp.add("11108");
        replicaSet.put("11124", temp);

        temp = null;
        temp = new HashSet<>();
        temp.add("11108");
        temp.add("11116");
        replicaSet.put("11112", temp);
    }

    private class Node {
        String portNum;
        String portNumHash;
        String nextPortNum;
        String nextPortHash;
        String prevPortNum;
        String prevPortHash;
        //Node prev;

        public Node(String portNumHash, String portNum, String nextPortHash, String nextPortNum, String prevPortHash, String prevPortNum) {
            Log.d(TAG, "port number:" + portNum + portNumHash);
            this.portNumHash = portNumHash;
            this.portNum = portNum;
            this.nextPortHash = nextPortHash;
            this.nextPortNum = nextPortNum;
            this.prevPortHash = prevPortHash;
            this.prevPortNum = prevPortNum;
        }
    }

    private String getPort(){
        TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        return String.valueOf((Integer.parseInt(portStr) * 2));
    }

    private void queryContext(){
        for(String file: keylist){
            try {
                FileInputStream in = getContext().openFileInput(file);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));

                String value = reader.readLine();
                Log.d(TAG, value);
                cursor.addRow(new Object[]{file, value.trim()});
            } catch (FileNotFoundException e) {
                Log.e(TAG, "File not found");
            } catch (IOException e) {
                Log.e(TAG, "IOException");
            }
        }
    }

    private void queryAll(ObjectOutputStream out){
        for(String file: getContext().fileList()){
            try {
                FileInputStream in = getContext().openFileInput(file);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));

                String value = reader.readLine();
                out.writeObject(new Object[]{file, value.trim()});
            } catch (FileNotFoundException e) {
                Log.e(TAG, "File not found");
            } catch (IOException e) {
                Log.e(TAG, "IOException");
            }
        }
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    @Override
	public synchronized int delete(Uri uri, String selection, String[] selectionArgs) {
		// TODO Auto-generated method stub
        //delcheck = 1;
        if(selection.equals("\"@\"")){
            for(String file: getContext().fileList()){
                getContext().deleteFile(file);
            }
        }else if (selection.equals("\"*\"")) {
            for(String file: getContext().fileList()){
                getContext().deleteFile(file);
            }
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", nodeList.portNum, nodeList.nextPortNum);
            while (!isDeleteAllComplete);
        }else {
            try {
                String hashKey = genHash(selection);
                if (hashKey.compareTo(hashPort.get("11124")) <= 0 || hashKey.compareTo(hashPort.get("11120")) > 0) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, "11124");

                    Set<String> replica = replicaSet.get("11124");
                    for (String set : replica) {
                        Log.d(TAG, "replicating-" + set);
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, set);
                    }
                } else if (hashKey.compareTo(hashPort.get("11124")) > 0 && hashKey.compareTo(hashPort.get("11112")) <= 0) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, "11112");

                    Set<String> replica = replicaSet.get("11112");
                    for (String set : replica) {
                        Log.d(TAG, "replicating-" + set);
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, set);
                    }
                } else if (hashKey.compareTo(hashPort.get("11112")) > 0 && hashKey.compareTo(hashPort.get("11108")) <= 0) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, "11108");

                    Set<String> replica = replicaSet.get("11108");
                    for (String set : replica) {
                        Log.d(TAG, "replicating-" + set);
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, set);
                    }
                } else if (hashKey.compareTo(hashPort.get("11108")) > 0 && hashKey.compareTo(hashPort.get("11116")) <= 0) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, "11116");

                    Set<String> replica = replicaSet.get("11116");
                    for (String set : replica) {
                        Log.d(TAG, "replicating-" + set);
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, set);
                    }
                } else if (hashKey.compareTo(hashPort.get("11116")) > 0 && hashKey.compareTo(hashPort.get("11120")) <= 0) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, "11120");

                    Set<String> replica = replicaSet.get("11120");
                    for (String set : replica) {
                        Log.d(TAG, "replicating-" + set);
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete", selection, set);
                    }
                }

//                try {
//                    Thread.sleep(1000);
//                }catch (InterruptedException ex){
//                    Log.e(TAG, "Thread Sleep Interrupted");
//                }
            }catch(NoSuchAlgorithmException e){
                Log.e(TAG, "No such algorithm excception");
            }
        }
		return 0;
	}

	@Override
	public String getType(Uri uri) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public synchronized Uri insert(Uri uri, ContentValues values) {
		// TODO Auto-generated method stub
        String key = "";
        String value = "";
        for(String column: values.keySet()) {
            if(column.equals("key")){
                key = (String) values.get(column);
            } else if(column.equals("value")){
                value = (String) values.get(column);
            }
        }

        try {
            String hashKey = genHash(key);
            Log.d(TAG, key);
            if (hashKey.compareTo(hashPort.get("11124")) <= 0 || hashKey.compareTo(hashPort.get("11120")) > 0) {
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, "11124");

                Set<String> replica = replicaSet.get("11124");
                for (String set : replica) {
                    Log.d(TAG, "replicating-" + set);
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, set);
                }
            } else if (hashKey.compareTo(hashPort.get("11124")) > 0 && hashKey.compareTo(hashPort.get("11112")) <= 0) {
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, "11112");

                Set<String> replica = replicaSet.get("11112");
                for (String set : replica) {
                    Log.d(TAG, "replicating-" + set);
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, set);
                }
            } else if (hashKey.compareTo(hashPort.get("11112")) > 0 && hashKey.compareTo(hashPort.get("11108")) <= 0) {
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, "11108");

                Set<String> replica = replicaSet.get("11108");
                for (String set : replica) {
                    Log.d(TAG, "replicating-" + set);
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, set);
                }
            } else if (hashKey.compareTo(hashPort.get("11108")) > 0 && hashKey.compareTo(hashPort.get("11116")) <= 0) {
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, "11116");

                Set<String> replica = replicaSet.get("11116");
                for (String set : replica) {
                    Log.d(TAG, "replicating-" + set);
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, set);
                }
            } else if (hashKey.compareTo(hashPort.get("11116")) > 0 && hashKey.compareTo(hashPort.get("11120")) <= 0) {
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, "11120");

                Set<String> replica = replicaSet.get("11120");
                for (String set : replica) {
                    Log.d(TAG, "replicating-" + set);
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, set);
                }
            }
        }catch (NoSuchAlgorithmException e){
            Log.e(TAG, "no such algorithm exception");
        }
        //new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key, value, getPort());
		return null;
	}

	@Override
	public boolean onCreate() {
		// TODO Auto-generated method stub

        avdPort.clear();

        avdPort.put("11108", "5554");
        avdPort.put("11112", "5556");
        avdPort.put("11116", "5558");
        avdPort.put("11120", "5560");
        avdPort.put("11124", "5562");

        nodeCollection.add("11108");
        nodeCollection.add("11112");
        nodeCollection.add("11116");
        nodeCollection.add("11120");
        nodeCollection.add("11124");

        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e(TAG, "Can't create a ServerSocket");
            return false;
        }

        String port = getPort();
        try {
            //Log.d(TAG, "port number:" + port + genHash(port));

            hashPort.put("11108", genHash(avdPort.get("11108")));
            hashPort.put("11112", genHash(avdPort.get("11112")));
            hashPort.put("11116", genHash(avdPort.get("11116")));
            hashPort.put("11120", genHash(avdPort.get("11120")));
            hashPort.put("11124", genHash(avdPort.get("11124")));

            if (port.equals("11108")) {
                nodeList = new Node(genHash(avdPort.get(port)), port, genHash(avdPort.get("11116")), "11116", genHash(avdPort.get("11112")), "11112");
            }else if(port.equals("11116")){
                nodeList = new Node(genHash(avdPort.get(port)), port, genHash(avdPort.get("11120")), "11120", genHash(avdPort.get("11108")), "11108");
            }else if(port.equals("11120")){
                nodeList = new Node(genHash(avdPort.get(port)), port, genHash(avdPort.get("11124")), "11124", genHash(avdPort.get("11116")), "11116");
            }else if(port.equals("11124")){
                nodeList = new Node(genHash(avdPort.get(port)), port, genHash(avdPort.get("11112")), "11112", genHash(avdPort.get("11120")), "11120");
            }else if(port.equals("11112")){
                nodeList = new Node(genHash(avdPort.get(port)), port, genHash(avdPort.get("11108")), "11108", genHash(avdPort.get("11124")), "11124");
            }else{
                Log.e(TAG, "Unknown port number");
            }

            //delete all files
            for(String file: getContext().fileList()){
                getContext().deleteFile(file);
            }

            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "backup");
        }catch (NoSuchAlgorithmException e){
            Log.e(TAG, "No such algorithm exception");
        }

        return false;
	}

	@Override
	public synchronized Cursor query(Uri uri, String[] projection, String selection,
			String[] selectionArgs, String sortOrder) {
		// TODO Auto-generated method stub
        //Log.v("query", selection);
        cursor = new MatrixCursor(new String[]{"key", "value"});
//        if(delcheck ==1){
//            return cursor;
//        }

        if(selection.equals("\"@\"")){
            queryContext();
        }else if (selection.equals("\"*\"")){
            queryContext();

            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "*", nodeList.portNum, nodeList.nextPortNum);
            //while (!isQueryAllComplete);
            try {
                Thread.sleep(2000);
            }catch (InterruptedException ex){
                Log.e(TAG, "Thread Sleep Interrupted");
            }
        } else{
            /*try {
                FileInputStream in = getContext().openFileInput(selection);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));

                String value = reader.readLine();
                cursor.addRow(new Object[]{selection, value.trim()});
            } catch (FileNotFoundException e) {
                Log.e(TAG, "File not found");*/
                tempKey = selection;
            wait = 1;
                String hashKey = null;
                try {
                    hashKey = genHash(selection);
                    Log.e(TAG, "In content query:" + selection);
                }catch (NoSuchAlgorithmException ex){
                    Log.e(TAG, "No such algorithm exception");
                }

                if(hashKey.compareTo(hashPort.get("11124")) <= 0 || hashKey.compareTo(hashPort.get("11120")) > 0){
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, "11124", nodeList.portNum);

                    Set<String> replica = replicaSet.get("11124");
                    for(String set: replica){
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, set, nodeList.portNum);
                    }
                }else if (hashKey.compareTo(hashPort.get("11124")) > 0 && hashKey.compareTo(hashPort.get("11112")) <= 0) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, "11112", nodeList.portNum);

                    Set<String> replica = replicaSet.get("11112");
                    for(String set: replica){
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, set, nodeList.portNum);
                    }
                }else if (hashKey.compareTo(hashPort.get("11112")) > 0 && hashKey.compareTo(hashPort.get("11108")) <= 0) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, "11108", nodeList.portNum);

                    Set<String> replica = replicaSet.get("11108");
                    for(String set: replica){
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, set, nodeList.portNum);
                    }
                }else if (hashKey.compareTo(hashPort.get("11108")) > 0 && hashKey.compareTo(hashPort.get("11116")) <= 0){
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, "11116", nodeList.portNum);

                    Set<String> replica = replicaSet.get("11116");
                    for(String set: replica){
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, set, nodeList.portNum);
                    }
                }else if (hashKey.compareTo(hashPort.get("11116")) > 0 && hashKey.compareTo(hashPort.get("11120")) <= 0) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, "11120", nodeList.portNum);

                    Set<String> replica = replicaSet.get("11120");
                    for(String set: replica){
                        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, set, nodeList.portNum);
                    }
                }
                //File is not in this node. Search the remaining nodes
                //new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query", selection, nodeList.nextPortNum, nodeList.portNum);
                //try {
                //    Thread.sleep(1000);
                //}catch (InterruptedException ex){
                //    Log.e(TAG, "Thread Sleep Interrupted");
                //}

                while(wait == 1){}
            /*} catch (IOException e) {
                Log.e(TAG, "IOException");
            }*/
        }

        return cursor;
	}

	@Override
	public int update(Uri uri, ContentValues values, String selection,
			String[] selectionArgs) {
		// TODO Auto-generated method stub
		return 0;
	}

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            //Used for insert
            Set<String> customize = new HashSet<>();
            //Used for node join
            Set<String> joinSet = new HashSet<>();

            while(true) {
                try {
                    Socket socket = serverSocket.accept();
                    ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

                    String input = "";
                    try {
                        input = (String) in.readObject();
                    } catch (ClassNotFoundException e) {
                        Log.e(TAG, "ServerTask Class Not Found Exception");
                    }
                    //Log.e(TAG, input);

                    if (input == null) {
                        continue;
                    }

                    if(input.equals("default")){
                        String[] msg = null;
                        try {
                            msg = ((String)in.readObject()).split(":");
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                        //Log.d(TAG, nodeList.portNum + " " + nodeList.nextPortNum + " " + nodeList.prevPortNum);

                        /*String hashKey = null;
                        try {
                            hashKey = genHash(msg[0]);
                            //Log.d(TAG, hashKey);
                        }catch (NoSuchAlgorithmException e){
                            Log.e(TAG, "No such algorithm exception");
                        }*/

                        persistInformation(msg);
                        /*if(((hashKey.compareTo(nodeList.prevPortHash) > 0)&& (hashKey.compareTo(nodeList.portNumHash) <= 0))
                            || ((nodeList.portNumHash.compareTo(nodeList.nextPortHash) < 0) &&
                                (nodeList.portNumHash.compareTo(nodeList.prevPortHash) < 0) &&
                                ((hashKey.compareTo(nodeList.prevPortHash) > 0) || (hashKey.compareTo(nodeList.portNumHash) < 0)))){
                            //Key belongs to this node
                            persistInformation(msg);
                            Set<String> forwardTo = replicaSet.get(getPort());
                            for (String set : forwardTo) {
                                Log.d(TAG, "replicating-" + set);
                                writeToServer("replicate", msg[0] + ":" + msg[1], set);
                            }
                        }else {
                            writeToServer("default", msg[0] + ":" + msg[1], nodeList.nextPortNum);
                        }*/
                    }else if(input.equals("replicate")){
                        String[] msg = null;
                        try {
                            msg = ((String)in.readObject()).split(":");
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }

                        persistInformation(msg);
                    }else if(input.equals("query")) {
                        String buffer = null;

                        try {
                            buffer = (String)in.readObject();
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }

                        String[] msg = buffer.split(":");
                        try {
                            FileInputStream stream = getContext().openFileInput(msg[0]);
                            Log.d(TAG, "In query:" + msg[0]);
                            BufferedReader reader = new BufferedReader(new InputStreamReader(stream));

                            String value = reader.readLine();
                            reader.close();

                            try {
                                Socket temp = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        Integer.parseInt(msg[1]));

                                ObjectOutputStream out = new ObjectOutputStream(temp.getOutputStream());
                                out.writeObject("result");
                                out.writeObject(new Object[]{msg[0], value.trim()});
                                //Log.d(TAG, msg[0] + value);
                                out.close();

                                temp.close();
                            } catch (UnknownHostException e) {
                                Log.e(TAG, "Client Task Unknown Host exception");
                            } catch (IOException e) {
                                Log.e(TAG, "Client Task socket IOException");
                            }
                        } catch (FileNotFoundException e) {
                            Log.e(TAG, "File not found");

                            //File is not in this node. Search the remaining nodes
                            writeToServer("query", buffer, nodeList.nextPortNum);
                        } catch (IOException e) {
                            Log.e(TAG, "IOException");
                        }
                    }else if(input.equals("result")) {
                        try {
                            Object[] result = (Object[]) in.readObject();
                            //Log.d(TAG, result.toString());
                            if(wait==1 && result[0].equals(tempKey)) {
                                cursor.addRow(result);
                                wait = 0;
                            }
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                    }else if(input.equals("*")) {
                        try {
                            String sourcePort = (String)in.readObject();

                            //if(!nodeList.portNum.equals(sourcePort)){
                                //Retrieve results from other nodes
                                //writeToServer("*", sourcePort, nodeList.nextPortNum);

                                Socket returnToSource = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                        Integer.parseInt(sourcePort));
                                ObjectOutputStream out = new ObjectOutputStream(returnToSource.getOutputStream());
                                out.writeObject("*result");
                                //Send the results to the requested node once found.
                                queryAll(out);
                                out.close();
                                returnToSource.close();
                            /*}else{
                                isQueryAllComplete = true;
                            }*/

                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                    }else if(input.equals("*result")){
                        try{
                            Object[] result = null;
                            while ((result = (Object[])in.readObject()) != null){
                                Log.d(TAG, result.toString());
                                cursor.addRow(result);
                            }
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }
                    }else if(input.equals("backup")){
                        String dest = null;
                        StringBuilder result = new StringBuilder();

                        try {
                            dest = (String)in.readObject();
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }

                        for(String file: getContext().fileList()){
                            try {
                                FileInputStream ip = getContext().openFileInput(file);
                                BufferedReader reader = new BufferedReader(new InputStreamReader(ip));

                                String value = reader.readLine();
                                //out.writeObject(new Object[]{file, value.trim()});
                                if(checkIfValid(file, dest)){
                                    result.append(file);
                                    result.append(":");
                                    result.append(value);
                                    result.append("-");
                                }
                            } catch (FileNotFoundException e) {
                                Log.e(TAG, "File not found");
                            } catch (IOException e) {
                                Log.e(TAG, "IOException");
                            }
                        }

                        if(result.length() > 0) {
                            result.deleteCharAt(result.length() - 1);
                            writeToServer("retrieve", result.toString(), dest);
                        }
                    }else if(input.equals("retrieve")){
                        String[] msg = null;
                        try {
                            msg = ((String)in.readObject()).split("-");
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }

                        for(int count = 0; count < msg.length; count++) {
                            String[] files = null;

                            files = msg[count].split(":");
                            persistInformation(files);
                        }
                    }else if(input.equals("delete")){
                        String selection = null;

                        try {
                            selection = (String)in.readObject();
                        }catch (ClassNotFoundException e){
                            Log.e(TAG, "ServerTask Class Not Found Exception");
                        }

                        getContext().deleteFile(selection);
                        keylist.remove(selection);
                    }
                }catch (IOException e){
                    Log.e(TAG, "IO exception in ServerTask");
                }catch (NullPointerException e){
                    Log.e(TAG, "Null Pointer Exception");
                }
            }
            //return null;
        }

        private void writeToServer(String firstMsg, String secondMsg, String port){
            try {
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(port));

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(firstMsg);
                out.writeObject(secondMsg);
                socket.close();
            } catch (UnknownHostException e) {
                Log.e(TAG, "Client Task Unknown Host exception");
            } catch (IOException e) {
                Log.e(TAG, "Client Task socket IOException");
            }
        }

        private void persistInformation(String[] msg){
            Log.e(TAG, "Persisting information:" + msg[0]);
            try {
                keylist.add(msg[0]);
                FileOutputStream file = getContext().openFileOutput(msg[0], Context.MODE_PRIVATE);

                file.write(msg[1].getBytes());
                file.close();
            } catch (FileNotFoundException e) {
                Log.e(TAG, "File Not found");
            } catch (IOException e) {
                Log.e(TAG, "Unable to write to file");
            }
        }

        private boolean checkIfValid(String key, String dest){
            boolean result = false;

            try{
                String hashKey = genHash(key);
                if(dest.equals("11124")) {
                    if ((hashKey.compareTo(hashPort.get("11124")) <= 0 || hashKey.compareTo(hashPort.get("11120")) > 0)
                        || (hashKey.compareTo(hashPort.get("11116")) > 0 && hashKey.compareTo(hashPort.get("11120")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11108")) > 0 && hashKey.compareTo(hashPort.get("11116")) <= 0)){
                        result = true;
                    }
                }else if(dest.equals("11112")) {
                    if ((hashKey.compareTo(hashPort.get("11124")) > 0 && hashKey.compareTo(hashPort.get("11112")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11116")) > 0 && hashKey.compareTo(hashPort.get("11120")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11124")) <= 0 || hashKey.compareTo(hashPort.get("11120")) > 0)){
                        result = true;
                    }
                }else if(dest.equals("11108")) {
                    if ((hashKey.compareTo(hashPort.get("11112")) > 0 && hashKey.compareTo(hashPort.get("11108")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11124")) > 0 && hashKey.compareTo(hashPort.get("11112")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11124")) <= 0 || hashKey.compareTo(hashPort.get("11120")) > 0)){
                        result = true;
                    }
                }else if(dest.equals("11116")) {
                    if ((hashKey.compareTo(hashPort.get("11108")) > 0 && hashKey.compareTo(hashPort.get("11116")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11112")) > 0 && hashKey.compareTo(hashPort.get("11108")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11124")) > 0 && hashKey.compareTo(hashPort.get("11112")) <= 0)){
                        result = true;
                    }
                }else if(dest.equals("11120")) {
                    if ((hashKey.compareTo(hashPort.get("11116")) > 0 && hashKey.compareTo(hashPort.get("11120")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11108")) > 0 && hashKey.compareTo(hashPort.get("11116")) <= 0)
                        || (hashKey.compareTo(hashPort.get("11112")) > 0 && hashKey.compareTo(hashPort.get("11108")) <= 0)){
                        result = true;
                    }
                }

                /*for(String node: replicaSet.keySet()){
                    if(node.equals(nodeList.portNum)){
                        for(String set: replicaSet.get(node)){
                            if(set.equals(dest)){
                                result = true;
                                break;
                            }
                        }
                    }
                }*/
            }catch (NoSuchAlgorithmException e){
                Log.d(TAG, "No such algorithm exception");
            }

            return result;
        }
    }

    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {
            if(msgs[0].equals("query")){
                writeToServer("query", msgs[1] + ":" + msgs[3], msgs[2]);
            }else if(msgs[0].equals("*")){
                String port = getPort();

                for(String node: nodeCollection){
                    if(!node.equals(port)){
                        writeToServer("*", port, node);
                    }
                }
                //writeToServer("*", msgs[1], msgs[2]);
            }else if(msgs[0].equals("backup")) {
                String port = getPort();

                for(String node: nodeCollection){
                    if(!node.equals(port)){
                        writeToServer("backup",port,node);
                    }
                }
            }else if(msgs[0].equals("delete")) {
                writeToServer("delete", msgs[1], msgs[2]);
            }else {
                String key = msgs[0];
                String value = msgs[1];

                replicate = true;
                writeToServer("default", key + ":" + value, msgs[2]);
            }
            return null;
        }

        private void writeToServer(String firstMsg, String secondMsg, String port){
            try{
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(port));

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(firstMsg);
                out.writeObject(secondMsg);
                out.flush();
                socket.close();
            } catch (UnknownHostException e) {
                Log.e(TAG, "Client Task Unknown Host exception");
            } catch (IOException e) {
                Log.e(TAG, "Client Task socket IOException");
            }
        }
    }
}
