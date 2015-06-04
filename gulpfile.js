var gulp = require('gulp');
var babel = require("gulp-babel");
var jshint = require('gulp-jshint');
var uglify = require('gulp-uglify');
var runseq = require('run-sequence');
var rename = require('gulp-rename');
var wrap = require('gulp-wrap');
var path = require('path');
var del = require('del');

const REL_DIR = __dirname;

gulp.task('jshint', function() {
	return gulp
		.src('src/polyauth.js')
		.pipe(jshint())
		.pipe(jshint.reporter('default'));
});

gulp.task('compile', function() {
	return gulp
		.src('src/polyauth.js')
		.pipe(babel())
		.pipe(gulp.dest(REL_DIR));
});

gulp.task('html', function() {
	return gulp
		.src(path.join(REL_DIR, 'polyauth.js'))
		.pipe(wrap('<script>\n\n<%= contents %>\n\n</script>'))
		.pipe(rename('polyauth.html'))
		.pipe(gulp.dest(REL_DIR));
});

gulp.task('min', function() {
	return gulp
		.src(path.join(REL_DIR, 'polyauth.js'))
		.pipe(uglify({preserveComments: 'some'}))
		.pipe(rename('polyauth.min.js'))
		.pipe(gulp.dest(REL_DIR));
});

gulp.task('distclean', ['depsclean', 'clean']);

gulp.task('depsclean', function(cb) {
  del([
    path.join(__dirname, 'bower_components'),
    path.join(__dirname, 'node_modules')
	], cb);
});

gulp.task('clean', function(cb) {
	del(['polyauth.html', 'polyauth.js', 'polyauth.min.js'], cb);
});

gulp.task('default', function(cb) {
	runseq('jshint', 'compile', ['html', 'min'], cb);
});
