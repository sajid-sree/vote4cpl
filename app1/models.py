from django.db import models
from django.contrib.auth.models import User

# Create your models here.




class vote(models.Model):
    Event = models.CharField(max_length=100)
    candidateName1 = models.CharField(max_length=100)
    candidateName2 = models.CharField(max_length=100)
    description = models.TextField()
    VotesCandidate1 = models.ManyToManyField(User, related_name='VotesCandidate1')
    VotesCandidate2 = models.ManyToManyField(User, related_name='VotesCandidate2')
    endtime = models.DateTimeField()

    def __str__(self):
        return self.Event
