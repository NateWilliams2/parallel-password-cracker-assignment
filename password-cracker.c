#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6

/************************* Part A *************************/
/********************* Parts B & C ************************/

// Checks if the hash for a candidate password is equal to the input hash
int check_hash_equal(char* candidate_passwd, uint8_t candidate_hash[], uint8_t* input_hash) {
  MD5((unsigned char*)candidate_passwd, strlen(candidate_passwd), candidate_hash); //< Do the hash

  // Now check if the hash of the candidate password matches the input hash
  if(memcmp(input_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
    return 0;
  } else {
    return -1;
  }
}

// Recersive part of increment_string
void increment_string_r(char string[], int index) {
  if (index >= 6){ // If all strings tried, signal end string
    string[0] = '\0';
    return;
  }
  string[index]++;

  if (string[index] > 'z') {
    string[index] = 'a';
    increment_string_r(string, index + 1);
  }
}

// Increment a string by one letter, string is 6 letters
void increment_string(char string[]) {
  increment_string_r(string, 0);
}

/**
 * Find a six character lower-case alphabetic password that hashes
 * to the given hash value. Complete this function for part A of the lab.
 *
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that holds the hash of a password
 * \param output      A pointer to memory with space for a six character password + '\0'
 * \returns           0 if the password was cracked. -1 otherwise.
 */
int crack_single_password(uint8_t* input_hash, char* output) {
  // Take our candidate password and hash it using MD5
  char candidate_passwd[7] = {'a', 'a', 'a', 'a', 'a', 'a', '\0'}; //< This variable holds the password we are trying
  uint8_t candidate_hash[MD5_DIGEST_LENGTH]; //< This will hold the hash of the candidate password

  // Exit loop once last valid password string is reached
  while (candidate_passwd[0] != '\0'){
    if (check_hash_equal(candidate_passwd, candidate_hash, input_hash) == 0) {
      strncpy(output, candidate_passwd, PASSWORD_LENGTH+1);
      return 0;
    } else {
      // If password not reached, increment to next candidate
      increment_string(candidate_passwd);
    }
  }
  //Check last string after exiting while loop
  // if (check_hash_equal(candidate_passwd, candidate_hash, input_hash) == 0) {
  //   strncpy(output, candidate_passwd, PASSWORD_LENGTH+1);
  //   return 0;
  // }
  return -1;
}

/********************* Parts B & C ************************/

/**
 * type to represent one node of linked-list of username/password pairs
 */
typedef struct node_t {
  char* username;
  uint8_t password_hash[MD5_DIGEST_LENGTH];
  struct node_t* next;
} node_t;

/**
 * This struct is the root of the data structure that will hold users and hashed passwords.
 * This could be any type of data structure you choose: list, array, tree, hash table, etc.
 * Implement this data structure for part B of the lab.
 */
typedef struct password_set {
  node_t* head;
} password_set_t;

/**
 * Initialize a password set.
 * Complete this implementation for part B of the lab.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */
void init_password_set(password_set_t* passwords) {
  passwords->head = NULL;
}

/**
 * Add a password to a password set
 * Complete this implementation for part B of the lab.
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 * \param username    The name of the user being added. The memory that holds this string's
 *                    characters will be reused, so if you keep a copy you must duplicate the
 *                    string. I recommend calling strdup().
 * \param password_hash   An array of MD5_DIGEST_LENGTH bytes that holds the hash of this user's
 *                        password. The memory that holds this array will be reused, so you must
 *                        make a copy of this value if you retain it in your data structure.
 */
void add_password(password_set_t* passwords, char* username, uint8_t* password_hash) {
  // Special case for head of list
  if (passwords->head == NULL){
    passwords->head = (node_t*) malloc(sizeof(node_t));
    passwords->head->username = (char*) malloc(sizeof(username));
    strcpy(passwords->head->username, username);
    memcpy(passwords->head->password_hash, password_hash, MD5_DIGEST_LENGTH);
    passwords->head->next = NULL;
  } else{
    node_t* node_ptr = passwords->head;
    // Case for other elements of list
      while (node_ptr -> next != NULL){
        node_ptr = node_ptr->next;
      }; // Loop to last element
    // Allocate new node, append to list
    node_ptr -> next = (node_t*) malloc(sizeof(node_t));
    node_ptr->next->username = (char*) malloc(sizeof(username));
    strcpy(node_ptr->next->username, username);
    memcpy(node_ptr->next->password_hash, password_hash, MD5_DIGEST_LENGTH);
    node_ptr->next->next = NULL;
  }
}

void remove_password(password_set_t* passwords, node_t* current, node_t* parent){
  if(current == passwords->head){ // If on first element of list
    passwords->head = current->next;
  } else{
    parent->next = current->next;
  }
  free(current->username);
  free(current);
}

/**
 * Crack all of the passwords in a set of passwords. The function should print the username
 * and cracked password for each user listed in passwords, separated by a space character.
 * Complete this implementation for part B of the lab.
 *
 * \returns The number of passwords cracked in the list
 */
int crack_password_list(password_set_t* passwords) {
  char candidate_passwd[7] = {'a', 'a', 'a', 'a', 'a', 'a', '\0'}; //< This variable holds the password we are trying
  uint8_t candidate_hash[MD5_DIGEST_LENGTH]; //< This will hold the hash of the candidate password
  int num_cracked = 0; // Number of cracked passwords

  // Exit loop once last valid password string is reached and/or all passwords are found
  while (candidate_passwd[0] != '\0' && passwords->head != NULL){
    node_t* parent = passwords->head;
    node_t* current = passwords->head;
    MD5((unsigned char*)candidate_passwd, strlen(candidate_passwd), candidate_hash); //< Hash candidate password
    while (current != NULL){ // Linear search through user list
      if(memcmp(current->password_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
        printf("%s %.6s\n", current->username, candidate_passwd);
        node_t* temp = current->next;
        remove_password(passwords, current, parent);
        current = temp;
        num_cracked++;
      } else {
        // If password not reached, move to next candidate
        if(current != passwords->head){ // On head of list, parent is not really parent and should be offset by one entry
          parent = current;
        }
        current = current->next; // Set current to next node
      }
    }
    // After testing every candidate, check next password
    increment_string(candidate_passwd);
  }
  return num_cracked;
}

/******************** Provided Code ***********************/

/**
 * Convert a string representation of an MD5 hash to a sequence
 * of bytes. The input md5_string must be 32 characters long, and
 * the output buffer bytes must have room for MD5_DIGEST_LENGTH
 * bytes.
 *
 * \param md5_string  The md5 string representation
 * \param bytes       The destination buffer for the converted md5 hash
 * \returns           0 on success, -1 otherwise
 */
int md5_string_to_bytes(const char* md5_string, uint8_t* bytes) {
  // Check for a valid MD5 string
  if(strlen(md5_string) != 2 * MD5_DIGEST_LENGTH) return -1;

  // Start our "cursor" at the start of the string
  const char* pos = md5_string;

  // Loop until we've read enough bytes
  for(size_t i=0; i<MD5_DIGEST_LENGTH; i++) {
    // Read one byte (two characters)
    int rc = sscanf(pos, "%2hhx", &bytes[i]);
    if(rc != 1) return -1;

    // Move the "cursor" to the next hexadecimal byte
    pos += 2;
  }

  return 0;
}

void print_usage(const char* exec_name) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s single <MD5 hash>\n", exec_name);
  fprintf(stderr, "  %s list <password file name>\n", exec_name);
}

int main(int argc, char** argv) {
  if(argc != 3) {
    print_usage(argv[0]);
    exit(1);
  }

  if(strcmp(argv[1], "single") == 0) {
    // The input MD5 hash is a string in hexadecimal. Convert it to bytes.
    uint8_t input_hash[MD5_DIGEST_LENGTH];
    if(md5_string_to_bytes(argv[2], input_hash)) {
      fprintf(stderr, "Input has value %s is not a valid MD5 hash.\n", argv[2]);
      exit(1);
    }

    // Now call the crack_single_password function
    char result[7];
    if(crack_single_password(input_hash, result)) {
      printf("No matching password found.\n");
    } else {
      printf("%s\n", result);
    }

  } else if(strcmp(argv[1], "list") == 0) {
    // Make and initialize a password set
    password_set_t passwords;
    init_password_set(&passwords);

    // Open the password file
    FILE* password_file = fopen(argv[2], "r");
    if(password_file == NULL) {
      perror("opening password file");
      exit(2);
    }

    int password_count = 0;

    // Read until we hit the end of the file
    while(!feof(password_file)) {
      // Make space to hold the username
      char username[MAX_USERNAME_LENGTH];

      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];

      // Make space to hold the MD5 bytes
      uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the newline
      if(fscanf(password_file, "%s %s ", username, md5_string) != 2) {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // Convert the MD5 string to MD5 bytes in our new node
      if(md5_string_to_bytes(md5_string, password_hash) != 0) {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }

      // Add the password to the password set
      add_password(&passwords, username, password_hash);
      password_count++;
    }

    // Now run the password list cracker
    int cracked = crack_password_list(&passwords);

    printf("Cracked %d of %d passwords.\n", cracked, password_count);

  } else {
    print_usage(argv[0]);
    exit(1);
  }

  return 0;
}
