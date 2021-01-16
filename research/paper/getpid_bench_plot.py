import matplotlib.pyplot as plt
import json
import sys

def main():
    data = json.load(sys.stdin)
    fig, ax = plt.subplots()
    plt.xscale('log')
    plt.yscale('log')
    subprocess = data['subprocess']
    rsyscall = data['rsyscall']
    ax.plot([10**x for x, y in subprocess], [y for x, y in subprocess], 'o-', label="Python subprocess")
    ax.plot([10**x for x, y in rsyscall], [y for x, y in rsyscall], '^-', label="rsyscall")
    ax.legend()
    
    ax.set(xlabel='Pages mapped in memory', ylabel='time (us)')
    ax.grid()
    
    fig.savefig(sys.stdout.buffer)

if __name__ == "__main__":
    main()
