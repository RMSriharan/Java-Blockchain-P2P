import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

class Transaction {
    public String sender, receiver;
    public double amount;
    public String signature;

    public Transaction(String sender, String receiver, double amount) {
        this.sender = sender;
        this.receiver = receiver;
        this.amount = amount;
    }

    public void signTransaction(PrivateKey privateKey) {
        String data = sender + receiver + amount;
        this.signature = applySignature(privateKey, data);
    }

    public boolean verifyTransaction(PublicKey publicKey) {
        String data = sender + receiver + amount;
        return verifySignature(publicKey, data, this.signature);
    }

    private static String applySignature(PrivateKey privateKey, String input) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(input.getBytes());
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean verifySignature(PublicKey publicKey, String input, String signature) {
        try {
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(publicKey);
            sign.update(input.getBytes());
            return sign.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            return false;
        }
    }
}

class Block {
    public int index, nonce;
    public String previousHash, hash;
    public ArrayList<Transaction> transactions = new ArrayList<>();

    public Block(int index, String previousHash) {
        this.index = index;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.hash = calculateHash();
    }

    public String calculateHash() {
        return SHA256(index + previousHash + transactions.toString() + nonce);
    }

    public void mineBlock(int difficulty) {
        String target = "0".repeat(difficulty);
        while (!hash.substring(0, difficulty).equals(target)) {
            nonce++;
            hash = calculateHash();
        }
        System.out.println("Block Mined: " + hash);
    }

    public void addTransaction(Transaction transaction) {
        if (transaction.verifyTransaction(Wallet.getPublicKey(transaction.sender))) {
            transactions.add(transaction);
        } else {
            System.out.println("Invalid transaction!");
        }
    }

    private static String SHA256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) hexString.append(String.format("%02x", b));
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

class Blockchain {
    public ArrayList<Block> chain = new ArrayList<>();
    public int difficulty;

    public Blockchain(int difficulty) {
        this.difficulty = difficulty;
        chain.add(new Block(0, "0"));  // Genesis block
    }

    public void addBlock(Block block) {
        block.mineBlock(difficulty);
        chain.add(block);
    }

    public boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block current = chain.get(i);
            Block previous = chain.get(i - 1);
            if (!current.hash.equals(current.calculateHash())) return false;
            if (!current.previousHash.equals(previous.hash)) return false;
        }
        return true;
    }
}

class Wallet {
    private KeyPair keyPair;
    private static ArrayList<Wallet> wallets = new ArrayList<>();
    public String address;

    public Wallet() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            this.keyPair = keyGen.generateKeyPair();
            this.address = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            wallets.add(this);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public static PublicKey getPublicKey(String address) {
        for (Wallet wallet : wallets) {
            if (wallet.address.equals(address)) {
                return wallet.getPublicKey();
            }
        }
        return null;
    }
}

class PeerNode {
    private static boolean running = true;

    public static void startServer(int port) {
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                while (running) {
                    Socket client = serverSocket.accept();
                    BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    System.out.println("Received: " + in.readLine());
                    client.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
    }

    public static void stopServer() {
        running = false;
    }

    public static void sendMessage(String ip, int port, String message) {
        try (Socket socket = new Socket(ip, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            out.println(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public class BlockchainDemo {
    public static void main(String[] args) {
        Blockchain blockchain = new Blockchain(3);  // Set mining difficulty
        PeerNode.startServer(5000);  // Start peer-to-peer server
        
        Scanner scanner = new Scanner(System.in);
        Wallet alice = new Wallet();
        Wallet bob = new Wallet();

        while (true) {
            System.out.println("\n1. Create Transaction");
            System.out.println("2. Mine Block");
            System.out.println("3. Check Blockchain Validity");
            System.out.println("4. Exit");
            System.out.print("Enter choice: ");
            
            int choice = scanner.nextInt();
            switch (choice) {
                case 1:
                    System.out.print("Enter amount: ");
                    double amount = scanner.nextDouble();
                    Transaction tx = new Transaction(alice.address, bob.address, amount);
                    tx.signTransaction(alice.getPrivateKey());
                    
                    Block block = new Block(blockchain.chain.size(), blockchain.chain.get(blockchain.chain.size() - 1).hash);
                    block.addTransaction(tx);
                    blockchain.addBlock(block);
                    
                    PeerNode.sendMessage("localhost", 5000, "New block added: " + block.hash);
                    break;

                case 2:
                    System.out.println("Mining new block...");
                    Block newBlock = new Block(blockchain.chain.size(), blockchain.chain.get(blockchain.chain.size() - 1).hash);
                    blockchain.addBlock(newBlock);
                    break;

                case 3:
                    System.out.println("\nBlockchain valid? " + blockchain.isChainValid());
                    break;

                case 4:
                    System.out.println("Exiting...");
                    scanner.close();
                    PeerNode.stopServer();
                    System.exit(0);
                    break;

                default:
                    System.out.println("Invalid choice! Try again.");
            }
        }
    }
}
