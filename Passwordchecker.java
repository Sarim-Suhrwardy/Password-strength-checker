import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Scanner;
import java.util.regex.Pattern;

public class PasswordChecker {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("🔒 Password Strength Checker 🔒");
        System.out.print("Enter a password to check: ");
        String password = scanner.nextLine();

        String strength = evaluateStrength(password);
        double entropy = calculateEntropy(password);

        System.out.println("\n[Analysis]");
        System.out.println("• Strength: " + strength);
        System.out.printf("• Entropy: %.2f bits\n", entropy);

        System.out.println("\n[Breach Check]");
        try {
            String result = checkHIBP(password);
            System.out.println(result);
        } catch (Exception e) {
            System.out.println("Error checking breach: " + e.getMessage());
        }

        scanner.close();
    }

    // Evaluate password strength
    public static String evaluateStrength(String password) {
        int length = password.length();
        int categories = 0;

        if (Pattern.compile("[a-z]").matcher(password).find()) categories++;
        if (Pattern.compile("[A-Z]").matcher(password).find()) categories++;
        if (Pattern.compile("[0-9]").matcher(password).find()) categories++;
        if (Pattern.compile("[^a-zA-Z0-9]").matcher(password).find()) categories++;

        if (length < 8 || categories < 2) return "Weak";
        else if (length <= 12) return "Medium";
        else return "Strong";
    }

    // Entropy estimation
    public static double calculateEntropy(String password) {
        int uniqueChars = (int) password.chars().distinct().count();
        return password.length() * (Math.log(uniqueChars) / Math.log(2));
    }

    // Breach check with HIBP API
    public static String checkHIBP(String password) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] hashBytes = sha1.digest(password.getBytes("UTF-8"));

        StringBuilder hash = new StringBuilder();
        for (byte b : hashBytes) {
            hash.append(String.format("%02X", b));
        }

        String prefix = hash.substring(0, 5);
        String suffix = hash.substring(5);

        URL url = new URL("https://api.pwnedpasswords.com/range/" + prefix);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");

        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            String[] parts = inputLine.split(":");
            if (parts[0].equalsIgnoreCase(suffix)) {
                return "⚠️ This password has been found in " + parts[1] + " breaches!";
            }
        }
        in.close();
        return "✅ This password has NOT been found in known breaches.";
    }
}
