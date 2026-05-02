import json
import random

class RiddleGenerator:
    def __init__(self, json_path="lexicon.json", account_seed=None):
        self.seed = account_seed
        try:
            with open(json_path, 'r') as file:
                self.lexicon = json.load(file)
                self.alphabet_keys = [k for k in self.lexicon.keys() if k.isalpha()]
        except FileNotFoundError:
            print(f"Error: File {json_path} doesn't exist!")
            self.lexicon = {}
            self.alphabet_keys = []

    def generate(self, password):
        if not self.lexicon:
            return "Lexicon is empty or doesn't exist."

        rng = random.Random(self.seed)
        riddle_words = []
        used_words = set()
        
        for char in password:
            char_lower = char.lower()
            
            # Check 1: Is the character in the JSON? (a-z, !, @)
            if char_lower in self.lexicon:
                available_words = self.lexicon[char_lower]
                unused_words = [w for w in available_words if w.lower() not in used_words]
                
                if unused_words:
                    word = rng.choice(unused_words)
                else:
                    word = rng.choice(available_words)
                
                used_words.add(word.lower())
                
                if char.isupper() and char_lower.isalpha():
                    word = word.capitalize()
                    
                riddle_words.append(word)
                
            # Check 2: Character not in JSON (Numbers & Other Symbols)
            else:
                if self.alphabet_keys:
                    # Take random alphabet letter as base
                    random_letter = rng.choice(self.alphabet_keys)
                    available_base_words = self.lexicon[random_letter]
                    
                    # Check unused words for base
                    unused_base_words = [w for w in available_base_words if w.lower() not in used_words]
                    
                    if unused_base_words:
                        base_word = rng.choice(unused_base_words)
                    else:
                        base_word = rng.choice(available_base_words)
                        
                    used_words.add(base_word.lower())
                    
                    # Paste numbers/symbols in front of the base word
                    combined_word = f"{char}{base_word}"
                    riddle_words.append(combined_word)
                else:
                    # Pure fallback if alphabet_keys is empty
                    riddle_words.append(char)
                
        return " ".join(riddle_words)

# --- TESTING ---
if __name__ == "__main__":
    print("=== Mnemonic Password Riddle Generator ===")
    
    seed_input = input("Account name: ")
    password_input = input("Password: ")
    
    if password_input.strip() and seed_input.strip():
        gen = RiddleGenerator(json_path="lexicon.json", account_seed=seed_input)
        
        print("\n" + "=" * 50)
        print(f"Password: {password_input}")
        print(f"Account name: {seed_input}")
        print(f"Riddle: {gen.generate(password_input)}")
        print("=" * 50)
    else:
        print("\nError: Account name and password can't be empty!")