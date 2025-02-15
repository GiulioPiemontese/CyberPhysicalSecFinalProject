from ProverClass import PROVER
from AggregatorClass import AGGREGATOR
from VerifierClass import VERIFIER
from OwnerClass import OWNER
import time
import matplotlib.pyplot as plt

def build_hierarchy(aggregators, provers, fan_out):
    """
    Build a balanced tree hierarchy of aggregators and assign provers evenly to the leaf aggregators.
    """
    if not aggregators:
        raise ValueError("There must be at least one aggregator.")

    # Build levels for aggregators.
    levels = []
    levels.append([aggregators[0]])  # Level 0 (root)
    current_index = 1

    # Partition the remaining aggregators into levels.
    while current_index < len(aggregators):
        parent_level = levels[-1]
        max_children = len(parent_level) * fan_out
        remaining = len(aggregators) - current_index
        count = min(max_children, remaining)
        next_level = aggregators[current_index: current_index + count]
        levels.append(next_level)
        current_index += count

    # Link each aggregator with its children (from the next level) in a round-robin manner.
    for level in range(len(levels) - 1):
        parents = levels[level]
        children = levels[level + 1]
        # Initialize parent's children list.
        for parent in parents:
            parent.set_children([])
        for idx, child in enumerate(children):
            parent = parents[idx % len(parents)]
            parent.children.append(child)

    # The last level contains the leaf aggregators.
    leaf_aggregators = levels[-1]
    # Distribute provers evenly among leaf aggregators.
    for i, prover in enumerate(provers):
        leaf_aggregators[i % len(leaf_aggregators)].children.append(prover)

    return levels

def print_tree(node, level=0):
    """
    Recursively prints the tree structure.
    Aggregator nodes are printed with the prefix "Aggregator:" and prover nodes with "Prover:".
    """
    indent = "  " * level
    # Assume aggregator nodes have a 'children' attribute.
    if hasattr(node, 'children'):
        print(f"{indent}Aggregator: {node}")
        for child in node.children:
            print_tree(child, level + 1)
    else:
        print(f"{indent}Prover: {node}")

def start_SANA(n, a, fan_out, verbose=True):
    """
    Set up and run the SANA protocol simulation.
      - Create n provers.
      - Create a aggregators.
      - Build a balanced tree of aggregators and assign provers to the leaves.
      - Optionally print the hierarchy.
      - Execute the token request and attestation process.
    """
    # Create prover nodes.
    provers = [PROVER(i) for i in range(n)]
        
    # Create the owner.
    owner = OWNER(provers)
    
    # Create aggregator nodes.
    aggregators = [AGGREGATOR(i, provers, owner) for i in range(a)]
    
    # Build a balanced hierarchy of aggregators and assign provers.
    build_hierarchy(aggregators, provers, fan_out)
    
    # Optionally print the tree hierarchy.
    if verbose:
        print("\nHierarchy Tree:")
        print_tree(aggregators[0])
    
    # Verification process.
    verifier = VERIFIER(owner, aggregators)
    verifier.tokenReq()
    verifier.Attestation(aggregators[0])

########## MAIN ##########

if __name__ == "__main__":

    fan_out_values = [2, 4, 8, 12]
    device_counts = [100, 120, 140, 160, 180, 200]
    
    # Dictionary to hold runtime results for each fan_out value.
    runtimes_by_fan = {fan: [] for fan in fan_out_values}
    
    # Loop over each fan-out value.
    for fan_out in fan_out_values:
        print(f"\n--- Testing for fan_out = {fan_out} ---")
        # For each total device count:
        for total_devices in device_counts:
            # Split total_devices: 60% provers and 40% aggregators.
            n_provers = int(0.6 * total_devices)
            n_aggregators = total_devices - n_provers
            
            # For large numbers, disable verbose printing to keep output clean.
            verbose = False
            
            print(f"Running simulation with {n_provers} provers and {n_aggregators} aggregators (Total: {total_devices})")
            start_time = time.time()
            start_SANA(n_provers, n_aggregators, fan_out, verbose=verbose)
            elapsed = time.time() - start_time
            runtimes_by_fan[fan_out].append(elapsed)
            print(f"Simulation completed in {elapsed:.4f} seconds.")
    
    # Plot the graph: x-axis = Total Number of Devices, y-axis = Runtime (seconds)
    plt.figure(figsize=(10, 6))
    for fan_out in fan_out_values:
        plt.plot(device_counts, runtimes_by_fan[fan_out], marker='o', linestyle='-', label=f'Fan-out = {fan_out}')
    plt.xlabel('Total Number of Devices')
    plt.ylabel('Runtime (seconds)')
    plt.title('SANA Protocol Runtime vs. Total Number of Devices\nfor Different n-ary Trees')
    plt.legend()
    plt.grid(True)
    plt.show()