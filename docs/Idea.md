## Policy Engine (As an example)

Responsible for enforcing rules such as:
1. Never automatically deleting:
   1. Operating-system directories
   2. Files belonging to currently installed applications
   3. User-created documents
   4. Source-control working trees
   5. Encrypted or unknown containers
   6. The only copy of a detected backup
   7. Anything classified with insufficient confidence
2. Only bounded tools (Just example, not exhaustive)
   1. `inspect_item`
   2. `inspect_directory`
   3. `find_duplicates`
   4. `show_application_owner`
   5. `estimate_recoverable_space`
   6. `propose_cleanup`
   7. `move_to_recycle_bin`

## Note

NO Ring 0