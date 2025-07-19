import os
import random

def save_uid_batches(input_dir, output_dir, batch_size=10):
    all_uids = [d for d in os.listdir(input_dir) if os.path.isdir(os.path.join(input_dir, d))]
    random.shuffle(all_uids)

    os.makedirs(output_dir, exist_ok=True)

    for i in range(0, len(all_uids), batch_size):
        batch = all_uids[i:i+batch_size]
        batch_filename = os.path.join(output_dir, f"{i // batch_size}.txt")
        with open(batch_filename, 'w', encoding='utf-8') as f:
            for uid in batch:
                f.write(uid + '\n')
        print(f"Writing: {batch_filename}, containing {len(batch)} UID")

save_uid_batches("clean_batch_xml", "clean_uid")
