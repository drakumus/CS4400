/* This is the main file for the `whoosh` interpreter and the part
   that you modify. */

#include <stdlib.h>
#include <stdio.h>
#include "csapp.h"
#include "ast.h"
#include "fail.h"

typedef struct stored_data
{
  pid_t pid;
  int readfd;
  int writefd;
  script_command* command;
} process_data;

static void run_script(script *scr);
static void run_group(script_group *group);
static void run_command(script_command *command, int fds[2]);
static void set_var(script_var *var, int new_value);
static void write_var_to(int fd, script_var *var);
static void read_to_var(int fd, script_var *var);
static int has_var(const char *name);
static void handle_c();

//make var lookup vector
static script_var vars[2048];
int num_var = 0;
//process tracking
process_data group_pd[2048];
int pd_count;

/* You probably shouldn't change main at all. */

int main(int argc, char **argv) {
  script *scr;
  signal (SIGINT, handle_c);  
  if ((argc != 1) && (argc != 2)) {
    fprintf(stderr, "usage: %s [<script-file>]\n", argv[0]);
    exit(1);
  } 
  memset(vars, 0, sizeof(vars)/sizeof(script_var));

  scr = parse_script_file((argc > 1) ? argv[1] : NULL);

  run_script(scr);

  return 0;
}

static void run_script(script *scr) {
  int i = 0;
  for(; i < scr->num_groups; i++)
  {
    run_group(&scr->groups[i]);
  }
}

static int assign_var(const char* name, const char* value) {
  for (int i=0; i < num_var; i++) {
    if (strcmp(name, vars[i].name) == 0) {
      vars[i].value = value;
      return i;
    }
  }
  vars[num_var].name = name;
  vars[num_var].value = value;
  num_var++;
  return (num_var-1);
}

static int my_read_to_var(int fd, const char* variable_name) 
{
  script_var temp_var;
  temp_var.name = NULL;
  temp_var.value = NULL;
  read_to_var(fd, &temp_var);
  temp_var.name = variable_name;
  return assign_var(temp_var.name, temp_var.value);      
}

static void close_parent(int readfd, int writefd, script_command* command)
{
  if(command->output_to != NULL)
  {
    int index;
    close(writefd);
    index = my_read_to_var(readfd, strdup(command->output_to->name));
    command->extra_data = &vars[index];
    close(readfd);
  } else if(command->input_from != NULL)
  {
    close(readfd);
    int h = has_var(command->input_from->name);
    if(h >= 0)
      write_var_to(writefd, &vars[h]);
    else
      fail("Var could not be found");
    close(writefd);
  }
}

static void check_exit_status(process_data* pd, int status) {
  if (pd->command->extra_data != NULL) 
  {
    if (WIFEXITED(status)) 
    {
      if (status != 0) 
      {
         set_var((script_var *)pd->command->extra_data, WEXITSTATUS(status));
      } 
    } 
    else if (WIFSIGNALED(status)) 
    {
      int termination_status = WTERMSIG(status);
      set_var((script_var *)pd->command->extra_data, -termination_status);
    }
  }
}

static void wait_for_child(process_data* pd) {
  int status;
  pid_t ret = waitpid(pd->pid, &status, 0);
  if (ret == -1) {
     fprintf(stderr, "-1 return from waitpid");
     return;
  }
  check_exit_status(pd, status);
}

static int run_single_command(process_data* pd, script_command *command)
{
  pid_t pid;
  int fds[2];
  
  if(command->output_to != NULL || command->input_from != NULL)
  {
    Pipe(fds);
  }
  pid = Fork();
  if(pid == 0)
  {
    run_command(command, fds);
  } else
  {
    if(command->pid_to != NULL)
    {
      script_var temp;
      temp.name = NULL;
      temp.value = NULL;
      set_var(&temp, pid);
      assign_var(command->pid_to->name, temp.value);
    }
    pd->pid = pid;
    pd->readfd = fds[0];
    pd->writefd = fds[1];
    pd->command = command;
  }
  return pid;
}

static void handle_c()
{
  int i;
  for (i=0; i < pd_count; i++)  
  {
    kill(group_pd[i].pid, SIGTERM);
    kill(group_pd[i].pid, SIGCONT);
    wait_for_child(&group_pd[i]);
  }
}

static void run_group(script_group *group) {
  /* You'll have to make run_group do better than this, too */
  pid_t pid;
  pd_count = 0;
  //process_data group_pd[2048];
  int i, j;
  for(i = 0; i < group->num_commands; i++)
  { 
    script_command* command = &group->commands[i];
    if (group->mode == GROUP_SINGLE) 
    {
      for (j=0; j < group->repeats; j++) 
      {
        pid = run_single_command(&group_pd[pd_count], command);
        if (pid != 0) 
        {
          close_parent(group_pd[pd_count].readfd, group_pd[pd_count].writefd, group_pd[pd_count].command);
          wait_for_child(&group_pd[pd_count]);
          pd_count++;
        }
      }
    } else 
    {
      for (j=0; j < group->repeats; j++) 
      {
        pid = run_single_command(&group_pd[pd_count], command);
        if (pid != 0) 
          pd_count++;
      }
    } 
  }

  if (group->mode == GROUP_AND) 
  {
    for (j = 0; j < pd_count; j++) 
    {
      close_parent(group_pd[j].readfd, group_pd[j].writefd, group_pd[j].command);
      wait_for_child(&group_pd[j]);
    }
  } else if (group->mode == GROUP_OR) 
  {
    pid_t first_exited_child;
    int status;

    if (pd_count > 0) 
    {
      for (j=0; j < pd_count; j++) 
        close_parent(group_pd[j].readfd, group_pd[j].writefd, group_pd[j].command);
      first_exited_child = waitpid(-1, &status, 0);
      if (first_exited_child == -1)
        fail("Error waiting for OR group command\n");
      for (j=0; j < pd_count; j++)  
      {
        if (group_pd[j].pid != first_exited_child) 
        {
          kill(group_pd[j].pid, SIGTERM);
          kill(group_pd[j].pid, SIGCONT);
          wait_for_child(&group_pd[j]);
        } else 
        {
          check_exit_status(&group_pd[j], status);
        }
      }
    }
  }
}

/* This run_command function is a good start, but note that it runs
   the command as a replacement for the `whoosh` script, instead of
   creating a new process. */

static void run_command(script_command *command, int fds[2]) {
  const char **argv;
  int i;

  if(command->output_to != NULL) 
  {
    dup2 (fds[1], STDOUT_FILENO);
    close(fds[0]);
  } 
  else if (command->input_from != NULL) {
    dup2 (fds[0], STDIN_FILENO);
    close(fds[1]);
  }
  
  argv = malloc(sizeof(char *) * (command->num_arguments + 2));
  argv[0] = command->program;

  for (i = 0; i < command->num_arguments; i++) {
    if (command->arguments[i].kind == ARGUMENT_LITERAL) {
      argv[i+1] = command->arguments[i].u.literal;
    } else {
      script_var* command_var = command->arguments[i].u.var;
      int h = has_var(command_var->name);
      if(h >= 0)
        argv[i+1] = vars[h].value;
      else
        fail("variable couldn't be found");
    }
  }
  
  argv[command->num_arguments + 1] = NULL;
  Execve(argv[0], (char * const *)argv, environ);
  free(argv);
}

/* You'll likely want to use this set_var function for converting a
   numeric value to a string and installing it as a variable's
   value: */
static void set_var(script_var *var, int new_value) {
  char buffer[32];
  free((void*)var->value);
  snprintf(buffer, sizeof(buffer), "%d", new_value);
  var->value = strdup(buffer);
}

//looks for a var
static int has_var(const char *name)
{
  int i = 0;
  for(;i < num_var; i++)
  {  
    if(strcmp(name, vars[i].name) == 0)
      return i;
  }
  return -1;
}

/* You'll likely want to use this write_var_to function for writing a
   variable's value to a pipe: */
static void write_var_to(int fd, script_var *var) {
  size_t len = strlen(var->value);
  ssize_t wrote = Write(fd, var->value, len);
  wrote += Write(fd, "\n", 1);
  if (wrote != len + 1)
    app_error("didn't write all expected bytes");
}

/* You'll likely want to use this write_var_to function for reading a
   pipe's content into a variable: */
static void read_to_var(int fd, script_var *var) {
  size_t size = 4097, amt = 0;
  char buffer[size];
  ssize_t got;

  while (1) {
    got = Read(fd, buffer + amt, size - amt);
    if (!got) {
      if (amt && (buffer[amt-1] == '\n'))
        amt--;
      buffer[amt] = 0;
      free((void*)var->value);
      var->value = strdup(buffer);
      return;
    }
    amt += got;
    if (amt > (size - 1))
      app_error("received too much output");
  }
}
