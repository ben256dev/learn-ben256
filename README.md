# Ebook App

## CLI Testing Instructions

First clone this repository:

```bash
git clone https://github.com/BSU-CS-208-Spring-2023/5-1-final-project-final-project-3.git
```

After navigating to the root of the directory, you can attempt to create an account with the CLI (courtesy of ChatGPT).

```bash
# get an idea for the commands
./test/256cli.sh 
```

You should see

```bash
Usage: 256cli.sh <command> [arguments]

Commands:
  register <username> <password> <email>
      Register a new user.

  login <username> <password>
      Login an existing user.

  forgot-password <email>
      Request a password reset link.

  reset-password <token> <newpassword>
      Reset password using the token.

*THIS CLI WAS WRITTEN BY CHATGPT*
```

Try to run the account managment commands with your own username, password, and email

```bash
$ ./test/256cli.sh register <username> <password> <email>
{
  "success": true
}

It may take a moment before you see the success message. If you want, verify check that you *cannot* log in by skipping to the next step before verifying your email.

Check your email and click the link to verify your email!

Next try logging in.

```bash
$ ./test/256/cli.sh login <username> <password>
{
  "success": true,
  "message": "Login successful"
}
```

Try sending a password reset link.

```bash
$ ./test/256cli.sh forgot-password <email>
{
  "success": true
}
```

You should receive a reset link at that email shortly, but unlike verifying your email, reseting your password requires you to provide more than just the token. Normally there would be a redirect to a frontend for this. But we will do it manually. To do this we have to find the reset email and copy the provided *link* not the link text. Your url will be formatted something like ``https://learn.ben256.com/a/reset-password?token=...``. Copy the big hex token in the token field and use it for the following command.

```bash
$ ./test/256cli.sh reset-password <reallybigtoken> <newpassword>
{
  "success": true
}
```

Now try loging in like before with your old password and the command will return ``"success": false``. It will only succeed once you provide the new password.

I will be clearing the database next week once the front-end is completed, so expect to have to re-do the registration process with the front-end instead.

## Project Spec

Here are my primary goals with this project:

1. Make something with a potential userbase

2. Experience implementing web authentication, and create a portfolio item

3. Build an app that I can sell

### Userbase

The userbase will be comprised of students. These are people who want to consume an incredibly concise Ebook / Textbook in a web-article format (think zybooks but with 2/3rds  of the fluff removed). Priority is building a format for written resources that people *actually* want to read, not only because it is assigned as part of some course.

I will be using the [FSRS algorithm](https://github.com/open-spaced-repetition/rs-fsrs-nodejs). From my research, this is among the two best spaced repetition algorithms available, and it is open source. Users will have the opportunity to complete various activities similar to zybooks. The difference being that when progressing through a lesson, a single type of activity is not repeated. Rather, the user completes the activity for the first time and that type of problem is put into a bank of problem sets which the FSRS algorithm will (1) always ensure the user knows how to complete with a success rate of 70%-95%, and (2) take advantage of the spacing effect to ensure the user spends *minimal* time reviewing problem set items in order to achieve the desired success rate.

This algorithm in conjunction with a concise written web resource makes this app a potential all-in-one solution to a student's study needs. Spaced repetition is proven to be the most effective study technique by the psychological and education literature, and consistent reviews in accordance with the algorithm seems likely to be more efficient than what humans achieve through manual study. In so far as homework is assigned to aid in exam performance, this algorithm can also serve as a replacement for assigned homework, especially in cases where homework content requires massed practice of course content. Such massed practice does not take advantage of the spacing effect, encourages cramming (which is associated with low exam confidence), and is not personalized.

Furthermore, a concise and well structured written web resource might be more useful for quick reference to a student than say, a lengthy print textbook intended to be a comprehensive reference for a particular subject. Which anecdotally, students don't tend to use if at all. I imagine such an app is likely be used most effectively in conjunction with lecture, such that the algorithm has already started having students review 5-12 problem types *prior* to attending the corresponding lecture for that content.

### Implementing Web Auth, FSRS

I have been wanting to implement web authentication for a really long time and I am starting to feel confident in my ability to do this. I think it would look really good on a portfolio, plus I already have email hosting bought for my domain which I don't really use anyways. My project relying heavily on FSRS allows me to focus on building a working project rather than trying to build my own systems from scratch (except for web auth).

I want to use a document-oriented database like MongoDB since I've already taken a whole relational database class and I want to try something different. I am going to be storing hashed credentials for my users, as well as all of their problem set items and the characteristics like item difficulty and whatever else the FSRS algorithm requires. The FSRS data will change frequently.

### Building a Sellable App

From my perspective it seems like selling courses or educational content online is very lucrative. This content is generally geared towards beginners which makes this a potential opportunity for me to actually make money through advertising on social media. I don't have strong formal qualifications but there are a lot of things I've learned that I want to make videos and teach people about. If I succeed in making this app, it would likely take me at minimum several months to actually start earning revenue. I would likely use a recurring payment model through Stripe, but I won't be worrying about that for purposes of this assignment.

### Stretch Goals

I acknowledge that setting up user authentication manually can be somewhat difficult, so in a sense, I consider my actual app idea to be something of a stretch goal. User authentication on it's own might take me two or three weeks. I don't know if I will actually be able to complete a sample lesson, and the app might just have a very bare appearance and sample problems for the sake of testing the app. I also prefer to not use AWS. I am hoping I can use my VPS and an nginx server, in which case I will set up my app under a sub-domain of ben256.com. Maybe it's possible to do both. Until I hear back from Shane I am unsure.

## Project Wireframe

TODO: Replace the wireframe below with you own design.

![wireframe](https://ben256.com/b/dbcf6d9258e956ff6703bb4f99b34caa2841123172b20a5f48ac98a3ec48879c/moqups.png)
