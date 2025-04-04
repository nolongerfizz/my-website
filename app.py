import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Create portfolio (to sell and buy without affecting the history)
db.execute("""
     CREATE TABLE IF NOT EXISTS portfolio (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            symbol TEXT NOT NULL,
            shares INTEGER NOT NULL,
            price NUMERIC NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
                );
""")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Fetch user's stock data from the database
    stocks = db.execute(
        "SELECT symbol, SUM(shares) as shares FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])

    # Fetch user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    # Calculate the total value of stocks
    total_value = 0
    for stock in stocks:
        stock_info = lookup(stock["symbol"])
        stock["price"] = stock_info["price"]
        stock["total"] = stock["shares"] * stock["price"]
        total_value += stock["total"]

    # Calculate grand total
    grand_total = cash + total_value

    # Format values to 2 decimal places
    cash = f"{cash:.2f}"
    total_value = f"{total_value:.2f}"
    grand_total = f"{grand_total:.2f}"

    # Pass data to the template
    return render_template("index.html", stocks=stocks, cash=cash, total_value=total_value, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        # Create transactions table
        db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            symbol TEXT NOT NULL,
            shares INTEGER NOT NULL,
            price NUMERIC NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
                );
            """)

        # Check for valid input
        try:
            shares_int = int(request.form.get("shares"))
        except:
            return apology("The value is not a valid integer", 403)

        if shares_int < 1:
            return apology("You must buy a positive number of shares", 403)

        # Make sure stock symbol is valid
        symbol = request.form.get("symbol")  # Get info from HTML
        stock = lookup(symbol)  # This returns a dictionary
        if stock:
            # Retrieve the user's cash balance
            balance = db.execute(
                "SELECT cash FROM users WHERE id = ?", session["user_id"]
            )
            cash = balance[0]["cash"]

            # Calculate the total cost of the shares
            shares_cost = stock["price"] * shares_int

            # Compare the total cost with the user's cash balance
            if cash >= shares_cost:

                # Update the user's cash balance
                db.execute("UPDATE users SET cash = cash - ? WHERE id = ?",
                           shares_cost, session["user_id"])

                # Check if the user already has shares of the stock
                existing_shares = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)

                if existing_shares:
                    # Update the shares count
                    db.execute("UPDATE portfolio SET shares = shares + ? WHERE user_id = ? AND symbol = ?", shares_int, session["user_id"], symbol)
                else:
                    # Insert a new row into the portfolio table
                    db.execute("INSERT INTO portfolio (user_id, symbol, shares) VALUES (?, ?, ?)", session["user_id"], symbol, shares_int)

                # Insert a new row into the transactions table
                db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                           session["user_id"], symbol, shares_int, stock["price"])

                return redirect("/")

            else:
                return apology("Can't afford", 403)
        else:
            return apology("Invalid stock symbol", 403)

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Fetch user's stock data from the database
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ?", session["user_id"])

    # Pass data to the template
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        # Get the stock symbol from the form
        symbol = request.form.get("symbol")

        # Look up the stock information
        stock = lookup(symbol)

        # Check if the stock was found
        if stock:
            # Render the result page with stock information
            return render_template("quoted.html", stock=stock)
        else:
            return apology("Invalid stock symbol", 403)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Ensure username and password were summited
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide a username", 403)
        elif not request.form.get("password"):
            return apology("must provide a password", 403)
        elif not request.form.get("confirmpassword"):
            return apology("must enter password confirmation", 403)

        # Ensure if password and confirmation password match
        if request.form.get("password") != request.form.get("confirmpassword"):
            return apology("passwords do not match")

        # Take and check if username already taken
        username = request.form.get("username")
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("username already taken", 403)

        # Get password
        password = request.form.get("password")
        print(password)

        # Generate hash password
        hashed_password = generate_password_hash(password)

        # Insert hashed password into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   username, hashed_password)

        # Redirect to login
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Query the database for the user's stocks
    rows = db.execute(
        "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])

    if request.method == "POST":
        # Get information the user provided in the form
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Verify if the user provide both symbol and shares
        if not symbol or not shares:
            return apology("Must provide symbol and shares", 403)

        # Verify if the input provided is valid
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("Shares must be a positive integer", 403)
        except ValueError:
            return apology("Shares must be a positive integer", 403)

        # Query database for the user's shares of the selected stock
        user_shares = db.execute(
            "SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)

        if not user_shares or user_shares[0]["total_shares"] < shares:
            return apology("Not enough shares", 403)

        # If not errors; Lookup the current stock price
        stock_price = lookup(symbol)

        # Calculate the total value
        total_value = stock_price["price"] * int(shares)

        # Update the user's cash balance
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",
                   total_value, session["user_id"])

        # Update the portfolio table
        db.execute("UPDATE portfolio SET shares = shares - ? WHERE user_id = ? AND symbol = ?", shares, session["user_id"], symbol)

        # Check if total shares are zero
        owned = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
        if owned[0]["shares"] == 0:
            db.execute("DELETE FROM portfolio WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)



        # Update the transaction SQL table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   session["user_id"], symbol, - shares, stock_price["price"])

        # If no shares owned by user, delete table
        # Query the updated total shares
        owned = db.execute(
            "SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)

        # Check if total shares are zero
        if owned[0]["total_shares"] == 0:
            db.execute("DELETE FROM transactions WHERE user_id = ? AND symbol = ?",
                       session["user_id"], symbol)
        return redirect("/")

    # Pass the list of stocks names to the template
    return render_template("sell.html", stocks=rows)
