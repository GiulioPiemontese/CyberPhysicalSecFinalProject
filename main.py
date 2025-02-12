from ProverClass import PROVER
from AggregatorClass import AGGREGATOR
from VerifierClass import VERIFIER
from OwnerClass import OWNER

def build_hierarchy(aggregators, provers, fan_out):
    """Assigns children to each aggregator dynamically based on fan-out."""
    if len(aggregators) < 1:
        raise ValueError("There must be at least one aggregator.")

    queue = [aggregators[0]]  # Start with the root aggregator
    agg_index = 1  # Track which aggregators are assigned
    while queue and agg_index < len(aggregators):
        parent = queue.pop(0)  # Get the next aggregator to assign children
        children = []
        for _ in range(fan_out):
            if agg_index < len(aggregators):
                children.append(aggregators[agg_index])
                queue.append(aggregators[agg_index])
                agg_index += 1
        parent.set_children(children)

    # Distribute Provers to leaf aggregators
    leaf_aggregators = [agg for agg in aggregators if not agg.children]
    for i, prover in enumerate(provers):
        parent_agg = leaf_aggregators[i % len(leaf_aggregators)]
        parent_agg.children.append(prover)  # Directly add Provers to the aggregator



def print_tree(aggregator, level=0):
    indent = "  " * level  # Add two spaces per level for indentation
    print(f"{indent}{aggregator}")  # Print the aggregator at this level
    
    for child in aggregator.children:
        if isinstance(child, AGGREGATOR):
            print_tree(child, level + 1)  # Recursively print children (aggregators) with increased indentation
        else:
            print(f"{indent}  {child}")  # If it's a PROVER, just print it (no children)



########## MAIN ##########

if __name__ == "__main__":

  a = 7   # a is the total number of aggregators of the network
  n = 5   # n is the total number of providers of the network
  # there is only one verifier and owner
          
  provers = []

  for i in range(n):
    provers.append(PROVER(i))
    
  owner = OWNER(provers)
  
  aggregators = []

  for agg in range(a):
    aggregators.append(AGGREGATOR(provers, owner))

  build_hierarchy(aggregators, provers, fan_out=2)

  # Print out the tree hierarchy of aggregators
  print("\nHierarchy Tree:")
  print_tree(aggregators[0])  # Start from the root aggregator (aggregators[0])

  verifier = VERIFIER(owner, aggregators)
  verifier.tokenReq()

  verifier.Attestation(aggregators[0])

