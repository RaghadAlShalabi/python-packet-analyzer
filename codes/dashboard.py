from flask import Flask, render_template

app = Flask(__name__)

analysis_data = {}


@app.route("/")
def home():

    return render_template(
        "index.html",
        data=analysis_data
    )


def run_dashboard(data):

    global analysis_data

    analysis_data = data

    app.run(debug=False, use_reloader=False)