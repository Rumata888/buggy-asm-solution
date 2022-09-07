# Buggy asm solution

This is the solution for the CTFZone task Buggy Asm (source [here](https://github.com/Rumata888/buggy-asm-task)).

Run
```bash
docker build -t barretenberg-solution .
```

For fast solution using cached bug-inducing points:
```bash
docker run -t barretenberg-solution sage --python -u mal_client.py fast cryptotraining.zone 1353
```
For slow solution with SMT:

```bash
docker run -t barretenberg-solution sage --python -u mal_client.py slow cryptotraining.zone 1353
```